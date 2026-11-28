#!/bin/bash
# Usage : ./iocs2yara.sh iocs.txt > iocs.yar
# iocs.txt : un hash par ligne (MD5, SHA1 ou SHA256), lignes # ignorées
echo 'import "hash"'
n=0
while read -r h || [ -n "$h" ]; do
    h=$(echo "$h" | tr -d '[:space:]' | tr 'A-F' 'a-f')
    case ${#h} in
        32) f=md5 ;;
        40) f=sha1 ;;
        64) f=sha256 ;;
        *)  continue ;;          # ligne vide, commentaire, valeur invalide
    esac
    [[ "$h" =~ ^[0-9a-f]+$ ]] || continue
    n=$((n+1))
    cat <<FIN

rule IOC_Hash_$(printf '%03d' "$n")
{
    meta:
        source = "$1"
        hash   = "$h"
    condition:
        hash.$f(0, filesize) == "$h"
}
FIN
done < "$1"