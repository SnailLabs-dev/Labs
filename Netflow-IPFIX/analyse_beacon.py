#!/usr/bin/env python3
"""
analyse_beacon.py — repérer les connexions régulières (beaconing) dans des flux nfdump.

Pour chaque couple (source, destination, port, protocole) ayant au moins
MIN_CONNEXIONS connexions, le script calcule l'intervalle moyen entre deux
connexions, son écart-type et le coefficient de variation
(CV = écart-type / moyenne). Plus le CV est proche de 0, plus le rythme est
régulier.

Une même connexion peut être exportée en plusieurs enregistrements (délai actif,
ou dernier ACK exporté à part par les versions récentes de nfpcapd) : les
enregistrements qui ont le même 5-tuple et commencent à moins de
RECOLLAGE secondes de la fin du précédent sont recollés en une connexion.

Compatible avec le format CSV de nfdump 1.7.3 et de nfdump 1.7.10.

Usage :
    python3 analyse_beacon.py ~/enquete
    python3 analyse_beacon.py ~/enquete "src net 10.0.0.0/24" 20
"""
import csv
import io
import statistics
import subprocess
import sys
from collections import defaultdict
from datetime import datetime

dossier = sys.argv[1] if len(sys.argv) > 1 else "."
filtre = sys.argv[2] if len(sys.argv) > 2 else "src net 10.0.0.0/24"
MIN_CONNEXIONS = int(sys.argv[3]) if len(sys.argv) > 3 else 20
RECOLLAGE = 10.0       # secondes
INTERVALLE_MIN = 1.0   # secondes : en dessous, ce sont des rafales, pas un rythme

sortie = subprocess.run(["nfdump", "-R", dossier, "-q", "-o", "csv", filtre],
                        capture_output=True, text=True, check=True).stdout
lignes = [l for l in sortie.splitlines() if l.count(",") > 5]
if lignes and not lignes[0][:1].isalpha():
    # Sortie -q sans en-tête : on la redemande avec l'en-tête.
    sortie = subprocess.run(["nfdump", "-R", dossier, "-o", "csv", filtre],
                            capture_output=True, text=True, check=True).stdout
    lignes = [l for l in sortie.splitlines() if l.count(",") > 5]

# Noms de colonnes selon la version de nfdump : (1.7.10, 1.7.3)
COL = {
    "debut": ("firstSeen", "ts"), "duree": ("duration", "td"),
    "src": ("srcAddr", "sa"), "dst": ("dstAddr", "da"),
    "sport": ("srcPort", "sp"), "dport": ("dstPort", "dp"),
    "proto": ("proto", "pr"), "octets": ("bytes", "ibyt"),
}
PROTOS = {"6": "TCP", "17": "UDP", "1": "ICMP"}


def champ(r, nom):
    for c in COL[nom]:
        if c in r and r[c] is not None:
            return r[c].strip()
    raise KeyError(f"colonne {nom} introuvable : vérifiez la version de nfdump")


def horodatage(texte):
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(texte, fmt).timestamp()
        except ValueError:
            pass
    return None


def duree(texte):
    try:
        return float(texte)
    except ValueError:  # format hh:mm:ss.mmm
        h, m, s = texte.split(":")
        return int(h) * 3600 + int(m) * 60 + float(s)


# 1. Lire les enregistrements et recoller les morceaux d'une même connexion
par_tuple = defaultdict(list)
for r in csv.DictReader(io.StringIO("\n".join(lignes))):
    t = horodatage(champ(r, "debut"))
    if t is None:
        continue
    proto = PROTOS.get(champ(r, "proto"), champ(r, "proto"))
    cle5 = (champ(r, "src"), champ(r, "dst"), champ(r, "sport"), champ(r, "dport"), proto)
    par_tuple[cle5].append([t, t + duree(champ(r, "duree")), int(champ(r, "octets") or 0)])

groupes = defaultdict(list)
for (sa, da, sp, dp, pr), enregs in par_tuple.items():
    enregs.sort()
    connexions = []
    for debut, fin, octets in enregs:
        if connexions and debut - connexions[-1][1] <= RECOLLAGE:
            connexions[-1][1] = max(connexions[-1][1], fin)
            connexions[-1][2] += octets
        else:
            connexions.append([debut, fin, octets])
    groupes[(sa, da, dp, pr)].extend((c[0], c[2]) for c in connexions)

# 2. Mesurer la régularité par couple (source, destination, port, protocole)
resultats = []
for cle, conns in groupes.items():
    if len(conns) < MIN_CONNEXIONS:
        continue
    conns.sort()
    inter = [b[0] - a[0] for a, b in zip(conns, conns[1:])]
    moy = statistics.mean(inter)
    if moy < INTERVALLE_MIN:
        continue  # rafales (balayage, etc.) : pas un rythme de beacon
    cv = statistics.pstdev(inter) / moy
    octets = [o for _, o in conns]
    omoy = statistics.mean(octets)
    cv_oct = statistics.pstdev(octets) / omoy if omoy else 0
    resultats.append((cv, cle, len(conns), moy, omoy, cv_oct))

resultats.sort()
print(f"{'Source':<15} {'Destination':<16} {'Port':>5} {'Proto':<5} {'Conn.':>5} "
      f"{'Interv. moy.':>12} {'CV interv.':>10} {'Octets moy.':>11} {'CV octets':>9}")
for cv, (sa, da, dp, pr), n, moy, omoy, cvo in resultats[:15]:
    print(f"{sa:<15} {da:<16} {dp:>5} {pr:<5} {n:>5} {moy:>10.1f} s {cv:>10.3f} {omoy:>11.0f} {cvo:>9.3f}")
if not resultats:
    print(f"Aucun couple avec au moins {MIN_CONNEXIONS} connexions pour le filtre « {filtre} ».")
