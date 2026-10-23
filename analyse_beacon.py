#!/usr/bin/env python3
"""
analyse_beacon.py — repérer les connexions régulières (beaconing) dans des flux nfdump.

Pour chaque couple (source, destination, port, protocole) ayant au moins
MIN_FLUX flux, le script calcule l'intervalle moyen entre deux connexions,
son écart-type et le coefficient de variation (CV = écart-type / moyenne).
Plus le CV est proche de 0, plus le rythme est régulier.

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
MIN_FLUX = int(sys.argv[3]) if len(sys.argv) > 3 else 20

sortie = subprocess.run(["nfdump", "-R", dossier, "-o", "csv", filtre],
                        capture_output=True, text=True, check=True).stdout
lignes = [l for l in sortie.splitlines() if l.count(",") > 5]
lecteur = csv.DictReader(io.StringIO("\n".join(lignes)))


def horodatage(texte):
    texte = texte.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(texte, fmt).timestamp()
        except ValueError:
            pass
    return None


groupes = defaultdict(list)
for r in lecteur:
    t = horodatage(r.get("ts", ""))
    if t is None:
        continue
    cle = (r["sa"], r["da"], r["dp"], r["pr"])
    groupes[cle].append((t, int(r.get("ibyt", 0) or 0)))

resultats = []
for cle, flux in groupes.items():
    if len(flux) < MIN_FLUX:
        continue
    flux.sort()
    inter = [b[0] - a[0] for a, b in zip(flux, flux[1:])]
    moy = statistics.mean(inter)
    if moy <= 0:
        continue
    cv = statistics.pstdev(inter) / moy
    octets = [o for _, o in flux]
    cv_oct = statistics.pstdev(octets) / statistics.mean(octets) if statistics.mean(octets) else 0
    resultats.append((cv, cle, len(flux), moy, statistics.mean(octets), cv_oct))

resultats.sort()
print(f"{'Source':<15} {'Destination':<16} {'Port':>5} {'Proto':<5} {'Flux':>5} "
      f"{'Interv. moy.':>12} {'CV interv.':>10} {'Octets moy.':>11} {'CV octets':>9}")
for cv, (sa, da, dp, pr), n, moy, omoy, cvo in resultats[:15]:
    print(f"{sa:<15} {da:<16} {dp:>5} {pr:<5} {n:>5} {moy:>10.1f} s {cv:>10.3f} {omoy:>11.0f} {cvo:>9.3f}")
if not resultats:
    print(f"Aucun couple avec au moins {MIN_FLUX} flux pour le filtre « {filtre} ».")
