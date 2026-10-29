#!/usr/bin/env python3
"""
Générateur du jeu d'enquête « Logistique Gatineau » — labo NetFlow/IPFIX.

Produit un pcap (Ethernet) dont on tire des flux avec :
    nfpcapd -r enquete.pcap -w <dossier>

Les paquets sont écrits en entier (caplen = longueur d'origine) ; la charge
utile est remplie de zéros, ce qui se compresse très bien avec gzip.
Les versions récentes de nfpcapd (1.7.10) ignorent les paquets tronqués.

Toutes les adresses externes sont dans les plages de documentation
(RFC 5737) et les domaines suspects utilisent le TLD réservé .example.

Usage : python3 gen_scenario.py [--seed 42] [--out enquete.pcap]
"""
import argparse
import math
import random
import struct
from datetime import datetime
from zoneinfo import ZoneInfo

ap = argparse.ArgumentParser()
ap.add_argument("--seed", type=int, default=42)
ap.add_argument("--out", default="enquete.pcap")
args = ap.parse_args()
R = random.Random(args.seed)

TZ = ZoneInfo("America/Toronto")
BASE = datetime(2026, 10, 14, 0, 0, 0, tzinfo=TZ).timestamp()


def T(h, m=0, s=0.0):
    return BASE + h * 3600 + m * 60 + s


# ---------------------------------------------------------------- réseau
GW = "10.0.0.1"          # pfSense : passerelle et résolveur DNS interne
SRV_FICHIERS = "10.0.0.10"
SRV_LINUX = "10.0.0.11"
POSTES = [f"10.0.0.{i}" for i in range(101, 111)]
PATIENT0 = "10.0.0.105"
ADMIN = "10.0.0.110"

C2_IP, C2_NAME = "198.51.100.77", "api.cdn-telemetrie.example"
DNS_EXT = "192.0.2.53"
TUNNEL_ZONE = "t.cdn-telemetrie.example"
NTP_IP = "192.0.2.123"
EXFIL_IP = "203.0.113.200"
MIRROIR_IP, MIRROIR_NAME = "203.0.113.50", "miroir.ubuntu.example"

WEB = [  # (nom, ip, poids)
    ("outlook.office365.com", "203.0.113.10", 10),
    ("teams.microsoft.com", "203.0.113.11", 8),
    ("www.google.com", "203.0.113.12", 8),
    ("login.microsoftonline.com", "203.0.113.13", 6),
    ("www.radio-canada.ca", "203.0.113.20", 3),
    ("www.lapresse.ca", "203.0.113.21", 3),
    ("www.youtube.com", "203.0.113.22", 3),
    ("sharepoint.com", "203.0.113.14", 5),
    ("www.linkedin.com", "198.51.100.20", 2),
    ("fournisseur-transport.ca", "198.51.100.21", 4),
    ("portail.douanes.example", "198.51.100.22", 3),
    ("cdn.jsdelivr.net", "198.51.100.23", 4),
    ("www.meteomedia.com", "198.51.100.24", 2),
    ("github.com", "198.51.100.25", 1),
]
WEB_W = [w for _, _, w in WEB]

ALL_INTERNAL = [GW, SRV_FICHIERS, SRV_LINUX] + POSTES


def mac_of(ip):
    if ip.startswith("10.0.0."):
        return bytes([2, 0, 0, 0, 0, int(ip.split(".")[3])])
    return bytes([2, 0, 0, 0, 0, 1])  # externe : vu via la passerelle


def ipb(ip):
    return bytes(int(x) for x in ip.split("."))


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


PKTS = []  # (ts, data, origlen)
_ipid = {}


def emit(ts, src, dst, proto, l4hdr, payload=b"", iplen=None, ttl=None):
    hdr_len = 20 + len(l4hdr)
    if iplen is None:
        iplen = hdr_len + len(payload)
    if ttl is None:
        ttl = 64 if src.startswith("10.") else 52
    ident = _ipid.get(src, R.randint(1000, 60000))
    _ipid[src] = (ident + 1) & 0xFFFF
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, iplen, ident, 0x4000, ttl,
                      proto, 0, ipb(src), ipb(dst))
    iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
    eth = mac_of(dst) + mac_of(src) + b"\x08\x00"
    data = eth + iph + l4hdr + payload
    PKTS.append((ts, data, 14 + iplen))


def tcp_hdr(sp, dp, seq, ack, flags, win=64240):
    return struct.pack("!HHIIBBHHH", sp, dp, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                       5 << 4, flags, win, 0, 0)


FIN, SYN, RST, PSH, ACK = 1, 2, 4, 8, 16
MSS = 1448


_PORTS_UTILISES = {58417}  # port fixe du scanner


def eph():
    """Port éphémère jamais réutilisé dans la journée : évite que les outils de
    flux fusionnent deux connexions distinctes qui auraient le même 5-tuple."""
    while True:
        p = R.randint(49152, 65535)
        if p not in _PORTS_UTILISES:
            _PORTS_UTILISES.add(p)
            return p


def tcp_session(t, cli, srv, dport, c_bytes, s_bytes, dur, sport=None,
                rtt=None, close=True):
    """Session TCP complète, données réparties sur la durée."""
    sport = sport or eph()
    rtt = rtt if rtt is not None else (0.0008 if srv.startswith("10.") else R.uniform(0.012, 0.035))
    cs, ss = R.getrandbits(32), R.getrandbits(32)
    emit(t, cli, srv, 6, tcp_hdr(sport, dport, cs, 0, SYN))
    emit(t + rtt, srv, cli, 6, tcp_hdr(dport, sport, ss, cs + 1, SYN | ACK))
    emit(t + rtt * 1.05, cli, srv, 6, tcp_hdr(sport, dport, cs + 1, ss + 1, ACK))
    cs += 1
    ss += 1
    start, end = t + rtt * 1.1, t + max(dur, rtt * 4)
    span = end - start
    events = []
    nc = max(1, math.ceil(c_bytes / MSS)) if c_bytes else 0
    ns = max(1, math.ceil(s_bytes / MSS)) if s_bytes else 0
    rem = c_bytes
    for i in range(nc):
        sz = min(MSS, rem)
        rem -= sz
        events.append((start + span * (i / max(nc, 1)) * 0.9 + R.uniform(0, span * 0.02), "c", sz))
    rem = s_bytes
    for i in range(ns):
        sz = min(MSS, rem)
        rem -= sz
        events.append((start + span * 0.05 + span * (i / max(ns, 1)) * 0.9 + R.uniform(0, span * 0.01), "s", sz))
    events.sort()
    since_ack = 0
    for ts, who, sz in events:
        if who == "c":
            emit(ts, cli, srv, 6, tcp_hdr(sport, dport, cs, ss, PSH | ACK), iplen=40 + sz)
            cs += sz
            emit(ts + rtt, srv, cli, 6, tcp_hdr(dport, sport, ss, cs, ACK))
        else:
            emit(ts, srv, cli, 6, tcp_hdr(dport, sport, ss, cs, ACK | (PSH if sz < MSS else 0)), iplen=40 + sz)
            ss += sz
            since_ack += 1
            if since_ack >= 2:
                emit(ts + 0.0002, cli, srv, 6, tcp_hdr(sport, dport, cs, ss, ACK))
                since_ack = 0
    if close:
        emit(end, cli, srv, 6, tcp_hdr(sport, dport, cs, ss, FIN | ACK))
        emit(end + rtt, srv, cli, 6, tcp_hdr(dport, sport, ss, cs + 1, FIN | ACK))
        emit(end + rtt * 1.05, cli, srv, 6, tcp_hdr(sport, dport, cs + 1, ss + 1, ACK))
    return sport


def udp(ts, src, dst, sp, dp, payload=b"", iplen=None):
    ln = 8 + len(payload) if iplen is None else iplen - 20
    emit(ts, src, dst, 17, struct.pack("!HHHH", sp, dp, ln, 0), payload,
         iplen=None if iplen is None else iplen)


def qname(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def dns_exchange(ts, cli, server, name, answer_ip=None, qtype=1, txt=None):
    tid = R.getrandbits(16)
    sp = eph()
    q = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + qname(name) + struct.pack("!HH", qtype, 1)
    udp(ts, cli, server, sp, 53, q)
    rtt = 0.0006 if server.startswith("10.") else R.uniform(0.015, 0.03)
    ans = b""
    an = 0
    if qtype == 1 and answer_ip:
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ipb(answer_ip)
        an = 1
    elif qtype == 16 and txt is not None:
        t = txt.encode()
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 0, len(t) + 1) + bytes([len(t)]) + t
        an = 1
    r = struct.pack("!HHHHHH", tid, 0x8180, 1, an, 0, 0) + qname(name) + struct.pack("!HH", qtype, 1) + ans
    udp(ts + rtt, server, cli, 53, sp, r)


def lognorm_bytes(median, sigma, lo, hi):
    return int(min(hi, max(lo, R.lognormvariate(math.log(median), sigma))))


# ------------------------------------------------------------ trafic de fond
def background():
    for host in POSTES:
        # arrivée vers 8 h, départ vers 17 h
        arrive = T(8, R.randint(0, 25), R.uniform(0, 59))
        lunch_s = T(11, R.randint(50, 59) + 0, 0) + R.uniform(0, 600)
        lunch_e = lunch_s + R.uniform(2700, 3600)
        leave = T(17, R.randint(0, 25), R.uniform(0, 59))
        n = R.randint(30, 40)
        for _ in range(n):
            while True:
                t = R.uniform(arrive, leave)
                if not (lunch_s < t < lunch_e):
                    break
            name, ip, _ = R.choices(WEB, WEB_W)[0]
            dns_exchange(t, host, GW, name, ip)
            burst = R.choice([1, 1, 2, 3])
            for b in range(burst):
                tb = t + 0.05 + b * R.uniform(0.01, 0.2)
                tcp_session(tb, host, ip, 443,
                            c_bytes=lognorm_bytes(2500, 0.8, 600, 40000),
                            s_bytes=lognorm_bytes(60000, 1.3, 2000, 2500000),
                            dur=R.uniform(0.4, 25))
        # partages de fichiers : normal vers SRV-FICHIERS
        for _ in range(R.randint(4, 8)):
            t = R.uniform(arrive, leave)
            tcp_session(t, host, SRV_FICHIERS, 445,
                        c_bytes=lognorm_bytes(20000, 1.0, 2000, 900000),
                        s_bytes=lognorm_bytes(300000, 1.2, 5000, 6000000),
                        dur=R.uniform(1, 40), sport=eph())
        # NTP : toutes les 1024 s pendant que le poste est allumé (régulier, légitime)
        t = arrive + R.uniform(5, 60)
        while t < leave:
            sp = eph()  # client NTP sur port éphémère (comme chrony)
            udp(t, host, NTP_IP, sp, 123, b"\x23" + b"\0" * 47)
            udp(t + R.uniform(0.015, 0.03), NTP_IP, host, 123, sp, b"\x24" + b"\0" * 47)
            t += 1024
    # NTP du serveur Linux, toute la journée
    t = T(0, 3, 17)
    while t < T(23, 59, 59):
        sp = eph()
        udp(t, SRV_LINUX, NTP_IP, sp, 123, b"\x23" + b"\0" * 47)
        udp(t + 0.021, NTP_IP, SRV_LINUX, 123, sp, b"\x24" + b"\0" * 47)
        t += 1024
    # administrateur légitime : SSH vers le serveur Linux le matin
    tcp_session(T(8, 31, 4.2), ADMIN, SRV_LINUX, 22, c_bytes=38000, s_bytes=210000, dur=1260)
    tcp_session(T(14, 2, 40.8), ADMIN, SRV_LINUX, 22, c_bytes=12000, s_bytes=64000, dur=410)
    # mises à jour du serveur (entrant, légitime)
    dns_exchange(T(12, 5, 3.0), SRV_LINUX, GW, MIRROIR_NAME, MIRROIR_IP)
    tcp_session(T(12, 5, 3.1), SRV_LINUX, MIRROIR_IP, 80, c_bytes=9000, s_bytes=2400000, dur=38)


# ----------------------------------------------------------------- l'attaque
def beacon():
    dns_exchange(T(8, 47, 10.4), PATIENT0, GW, C2_NAME, C2_IP)
    t = T(8, 47, 12.0)
    while t < T(23, 59, 0):
        tcp_session(t, PATIENT0, C2_IP, 443,
                    c_bytes=R.randint(512, 530), s_bytes=R.randint(281, 290),
                    dur=R.uniform(0.18, 0.26))
        t += R.uniform(54, 66)  # 60 s ± 10 % de gigue


def reconnaissance():
    # balayage ICMP du /24
    t = T(9, 3, 41.0)
    alive = set(ALL_INTERNAL)
    for i in range(1, 255):
        dst = f"10.0.0.{i}"
        if dst == PATIENT0:
            continue
        ts = t + i * 0.011
        ident = R.getrandbits(16)
        emit(ts, PATIENT0, dst, 1, struct.pack("!BBHHH", 8, 0, 0, ident, 1), b"\0" * 0)
        if dst in alive:
            emit(ts + 0.0005, dst, PATIENT0, 1, struct.pack("!BBHHH", 0, 0, 0, ident, 1))
    # balayage SYN des ports 1-1024 de SRV-LINUX (nmap -sS)
    t = T(9, 5, 2.0)
    ports = list(range(1, 1025))
    R.shuffle(ports)
    sp = 58417
    open_ports = {22}
    for k, p in enumerate(ports):
        ts = t + k * 0.0075
        emit(ts, PATIENT0, SRV_LINUX, 6, tcp_hdr(sp, p, 1000, 0, SYN, win=1024), iplen=44)
        if p in open_ports:
            emit(ts + 0.0004, SRV_LINUX, PATIENT0, 6, tcp_hdr(p, sp, 5000, 1001, SYN | ACK))
            emit(ts + 0.0006, PATIENT0, SRV_LINUX, 6, tcp_hdr(sp, p, 1001, 0, RST))
        else:
            emit(ts + 0.0004, SRV_LINUX, PATIENT0, 6, tcp_hdr(p, sp, 0, 1001, RST | ACK))
    # balayage SYN de SRV-FICHIERS sur quelques ports Windows
    t = T(9, 7, 30.0)
    for k, p in enumerate([21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 636, 1433, 3306, 3389, 5985, 8080]):
        ts = t + k * 0.009
        emit(ts, PATIENT0, SRV_FICHIERS, 6, tcp_hdr(sp, p, 1000, 0, SYN, win=1024), iplen=44)
        if p in (135, 139, 445, 3389, 5985):
            emit(ts + 0.0004, SRV_FICHIERS, PATIENT0, 6, tcp_hdr(p, sp, 7000, 1001, SYN | ACK))
            emit(ts + 0.0006, PATIENT0, SRV_FICHIERS, 6, tcp_hdr(sp, p, 1001, 0, RST))
        else:
            emit(ts + 0.0004, SRV_FICHIERS, PATIENT0, 6, tcp_hdr(p, sp, 0, 1001, RST | ACK))


def force_brute():
    t = T(9, 21, 10.0)
    for i in range(57):
        d = R.uniform(1.18, 1.24)
        tcp_session(t, PATIENT0, SRV_LINUX, 22,
                    c_bytes=R.randint(2280, 2300), s_bytes=R.randint(3190, 3215), dur=d)
        t += R.uniform(1.36, 1.44)
    # tentative réussie : session interactive longue
    tcp_session(t + 0.4, PATIENT0, SRV_LINUX, 22, c_bytes=46000, s_bytes=380000, dur=1110)


def mouvement_lateral():
    t = T(9, 52, 18.0)
    for k, dst in enumerate(["10.0.0.102", "10.0.0.103", "10.0.0.104", "10.0.0.107"]):
        tcp_session(t + k * 31.5, PATIENT0, dst, 445,
                    c_bytes=R.randint(150000, 260000), s_bytes=R.randint(40000, 70000),
                    dur=R.uniform(6, 14))
    tcp_session(T(9, 58, 44.0), PATIENT0, "10.0.0.108", 3389,
                c_bytes=310000, s_bytes=4800000, dur=640)


def tunnel_dns():
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    t = T(10, 20, 5.0)
    end = T(10, 51, 40.0)
    while t < end:
        label = "".join(R.choice(alphabet) for _ in range(R.randint(52, 60)))
        label2 = "".join(R.choice(alphabet) for _ in range(R.randint(40, 56)))
        name = f"{label}.{label2}.{TUNNEL_ZONE}"
        txt = "".join(R.choice(alphabet) for _ in range(R.randint(60, 90)))
        dns_exchange(t, PATIENT0, DNS_EXT, name, qtype=16, txt=txt)
        t += R.uniform(1.6, 2.6)


def retour_soir_et_exfiltration():
    # l'attaquant revient par le C2 et se reconnecte au serveur en SSH
    tcp_session(T(22, 9, 51.3), PATIENT0, SRV_LINUX, 22, c_bytes=21000, s_bytes=96000, dur=1580)
    # exfiltration depuis le serveur Linux (~40 Mo sortants)
    tcp_session(T(22, 14, 7.6), SRV_LINUX, EXFIL_IP, 443,
                c_bytes=41_900_000, s_bytes=180000, dur=1013, rtt=0.021)


background()
beacon()
reconnaissance()
force_brute()
mouvement_lateral()
tunnel_dns()
retour_soir_et_exfiltration()

PKTS.sort(key=lambda p: p[0])
SNAP = 65535
with open(args.out, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAP, 1))
    for ts, data, orig in PKTS:
        # Paquet complet : la charge utile est complétée par des zéros jusqu'à
        # la longueur IP déclarée (nfpcapd >= 1.7.10 rejette les paquets tronqués).
        data = data + b"\0" * (orig - len(data))
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        f.write(struct.pack("<IIII", sec, usec, len(data), orig))
        f.write(data)
print(f"{len(PKTS)} paquets écrits dans {args.out}")
