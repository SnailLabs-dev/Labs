/*
   snaillabs.yar — Règles YARA d'introduction
   Cours de surveillance préventive en cybersécurité — SnailLabs
*/

rule SnailLabs_Executable_Windows
{
    meta:
        description = "Fichier exécutable Windows (PE) : en-tête MZ et signature PE"
        author      = "SnailLabs"
        date        = "2026-11-16"

    condition:
        uint16(0) == 0x5A4D                      // "MZ" au début du fichier
        and uint32(uint32(0x3C)) == 0x00004550   // "PE\0\0" à l'adresse indiquée en 0x3C
}

rule SnailLabs_PowerShell_Telechargement
{
    meta:
        description = "Script contenant des commandes PowerShell typiques d'un téléchargeur"
        author      = "SnailLabs"
        date        = "2026-11-16"

    strings:
        $ps1 = "powershell" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "Invoke-WebRequest" nocase
        $dl4 = "Start-BitsTransfer" nocase
        $ex1 = "IEX" nocase fullword
        $ex2 = "Invoke-Expression" nocase
        $ob1 = "FromBase64String" nocase
        $ob2 = "-EncodedCommand" nocase

    condition:
        filesize < 1MB
        and $ps1
        and any of ($dl*)
        and any of ($ex*, $ob*)
}

rule SnailLabs_Archive_Contenant_Executable
{
    meta:
        description = "Archive ZIP qui contient un fichier .exe, .scr, .js ou .lnk"
        author      = "SnailLabs"
        date        = "2026-11-16"

    strings:
        $zip  = { 50 4B 03 04 }
        $ext1 = ".exe" nocase
        $ext2 = ".scr" nocase
        $ext3 = ".js" nocase
        $ext4 = ".lnk" nocase

    condition:
        $zip at 0 and any of ($ext*)
}
