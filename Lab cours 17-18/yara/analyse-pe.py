#!/usr/bin/env python3
"""
analyse-pe.py — Analyse statique d'un exécutable Windows (PE), sans l'exécuter.
Affiche les informations qu'un analyseur comme Strelka (ScanPe) fournirait :
identité déclarée, date de compilation, sections, imports, signature.

Usage :  python3 analyse-pe.py <fichier.exe>
Prérequis (Kali) :  sudo apt install -y python3-pefile
"""
import datetime
import hashlib
import sys

try:
    import pefile
except ImportError:
    sys.exit("Module pefile introuvable. Installe-le avec : sudo apt install -y python3-pefile")

# Fonctions Windows souvent utilisées pour charger du code en mémoire et l'exécuter
API_SURVEILLEES = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "CreateThread",
    "CreateRemoteThread", "WriteProcessMemory", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "URLDownloadToFileA", "URLDownloadToFileW",
    "InternetOpenA", "InternetOpenW", "IsDebuggerPresent", "CryptDecrypt",
}


def titre(t):
    print(f"\n=== {t} ===")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    chemin = sys.argv[1]
    data = open(chemin, "rb").read()
    if data[:2] != b"MZ":
        sys.exit("Ce fichier n'est pas un exécutable Windows (pas d'en-tête MZ).")
    pe = pefile.PE(data=data)

    titre("FICHIER")
    print(f"Taille      : {len(data):,} octets".replace(",", " "))
    print(f"MD5         : {hashlib.md5(data).hexdigest()}")
    print(f"SHA256      : {hashlib.sha256(data).hexdigest()}")
    print(f"Imphash     : {pe.get_imphash() or '-'}")
    arch = "64 bits" if pe.OPTIONAL_HEADER.Magic == 0x20B else "32 bits"
    sous_sys = {2: "interface graphique", 3: "console"}.get(pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem))
    print(f"Type        : {arch}, {sous_sys}")

    titre("DATE DE COMPILATION")
    ts = pe.FILE_HEADER.TimeDateStamp
    date = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    print(f"{date:%Y-%m-%d %H:%M:%S} UTC   (pe.timestamp = {ts})")
    if date > datetime.datetime.now(datetime.timezone.utc):
        print("⚠  Date dans le futur : elle a été falsifiée.")

    titre("IDENTITÉ DÉCLARÉE (informations de version)")
    trouve = False
    for info in getattr(pe, "FileInfo", []) or []:
        for entree in info:
            for table in getattr(entree, "StringTable", []):
                for cle, val in table.entries.items():
                    print(f"{cle.decode(errors='replace'):18}: {val.decode(errors='replace')}")
                    trouve = True
    if not trouve:
        print("(aucune)")

    titre("SIGNATURE NUMÉRIQUE")
    signe = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].Size > 0
    print("Signé" if signe else "⚠  Non signé   (pe.number_of_signatures == 0)")

    titre("SECTIONS (nom / taille / entropie)")
    for s in pe.sections:
        nom = s.Name.rstrip(b"\0").decode(errors="replace")
        part = s.SizeOfRawData / len(data) * 100
        ent = s.get_entropy()
        alerte = []
        if part > 50:
            alerte.append(f"{part:.0f} % du fichier")
        if ent > 7.2:
            alerte.append("entropie élevée : données compressées ou chiffrées?")
        print(f"{nom:10} {s.SizeOfRawData:>12,} octets   entropie {ent:4.2f}   {'⚠  ' + ', '.join(alerte) if alerte else ''}".replace(",", " "))

    titre("FONCTIONS IMPORTÉES À SURVEILLER")
    vues = []
    for dll in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in dll.imports:
            if imp.name and imp.name.decode(errors="replace") in API_SURVEILLEES:
                vues.append(f"{dll.dll.decode()} → {imp.name.decode()}")
    print("\n".join(vues) if vues else "(aucune)")
    print()


if __name__ == "__main__":
    main()
