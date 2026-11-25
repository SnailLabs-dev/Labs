#!/usr/bin/env bash
# =====================================================================
#  triage-zeek.sh — Triage d'une infection à partir des journaux Zeek
#  Équivalent « Zeek » de triage.sh (Suricata)
#
#  Usage :
#    ./triage-zeek.sh <dossier_de_logs>     # ex. sur Security Onion :
#                                            #   sudo ./triage-zeek.sh /nsm/import/<md5>
#    ./triage-zeek.sh capture.pcap [-x]     # lance Zeek localement (si installé)
#                                            #   -x : extrait aussi les fichiers transférés
#
#  Les journaux doivent être en JSON (format par défaut de Security Onion).
#  Les fichiers .log et .log.gz sont lus, même dans des sous-dossiers.
# =====================================================================

set -uo pipefail
CIBLE="${1:?Usage: $0 <dossier_de_logs | capture.pcap> [-x]}"
EXTRAIRE="${2:-}"

# ---------- 1. Obtenir un dossier de journaux ----------
if [[ -f "$CIBLE" ]]; then
  command -v zeek >/dev/null || { echo "Zeek n'est pas installé. Donne plutôt un dossier de logs."; exit 1; }
  DIR="zeek_$(basename "${CIBLE%.*}")"
  rm -rf "$DIR"; mkdir -p "$DIR"
  PCAP_ABS="$(readlink -f "$CIBLE")"
  SCRIPTS=(frameworks/files/hash-all-files)
  [[ "$EXTRAIRE" == "-x" ]] && SCRIPTS+=(frameworks/files/extract-all-files)
  ( cd "$DIR" && zeek -C -r "$PCAP_ABS" LogAscii::use_json=T "${SCRIPTS[@]}" )
  echo "Journaux Zeek écrits dans $DIR/"
  [[ "$EXTRAIRE" == "-x" ]] && echo "Fichiers extraits dans $DIR/extract_files/  (⚠ maliciels réels : ne pas ouvrir!)"
elif [[ -d "$CIBLE" ]]; then
  DIR="$CIBLE"
else
  echo "Introuvable : $CIBLE"; exit 1
fi

# ---------- 2. Outils ----------
# lire <nom> : concatène toutes les lignes JSON des journaux <nom>.log et <nom>.*.log(.gz)
lire() {
  find "$DIR" -type f \( -name "$1.log" -o -name "$1.log.gz" -o -name "$1.*.log" -o -name "$1.*.log.gz" \) -print0 \
    | xargs -0 -r zcat -f 2>/dev/null | grep '^{' || true
}
titre() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"; }
PRIVE='^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)'
NON_ROUTABLE='^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|224\.|239\.|255\.|0\.|169\.254\.|ff0|fe80)'

if [[ -z "$(lire conn | head -1)" ]]; then
  echo "Aucun conn.log JSON trouvé dans $DIR. Vérifie le chemin ou le format (JSON requis)."; exit 1
fi

# ---------- 3. Rapport ----------
titre "HÔTES INTERNES LES PLUS ACTIFS (nb de connexions initiées)"
lire conn | jq -r '."id.orig_h"' | grep -E "$PRIVE" | sort | uniq -c | sort -rn | head -5

titre "HOSTNAMES — DHCP (IP / MAC / hostname / FQDN)"
lire dhcp | jq -r 'select(.host_name != null or .client_fqdn != null)
  | [(.assigned_addr // .client_addr // "-"), (.mac // "-"), (.host_name // "-"), (.client_fqdn // "-")] | @tsv' | sort -u

titre "COMPTES — Kerberos (IP / client / service / succès)"
lire kerberos | jq -r 'select(.client != null)
  | [."id.orig_h", .client, (.service // "-"), ((.success // "-")|tostring)] | @tsv' | sort -u

titre "COMPTES — NTLM (IP / domaine / utilisateur / hostname)"
lire ntlm | jq -r '[."id.orig_h", (.domainname // "-"), (.username // "-"), (.hostname // "-")] | @tsv' | sort -u

titre "FICHIERS TRANSFÉRÉS (type MIME / taille / SHA256 ou MD5 / source / nom)"
lire files | jq -r '[(.mime_type // "?"), ((.seen_bytes // .total_bytes // 0)|tostring),
    (.sha256 // .md5 // "-"), (.source // "-"),
    ((."id.resp_h" // (.tx_hosts // [])[0] // "-")|tostring), (.filename // "-")] | @tsv' | sort -u

titre "DOMAINES DNS DEMANDÉS (top 30)"
lire dns | jq -r '.query // empty' | sort | uniq -c | sort -rn | head -30

titre "HTTP (serveur / méthode / hôte / URI / User-Agent / type de réponse)"
lire http | jq -r '[."id.resp_h", (.method // "-"), (.host // "-"), ((.uri // "-")[0:70]),
    ((.user_agent // "-")[0:45]), ((.resp_mime_types // ["-"])|join(","))] | @tsv' | sort -u | head -40

titre "TLS (serveur:port / SNI / version / établi)"
lire ssl | jq -r '[."id.resp_h" + ":" + (."id.resp_p"|tostring), (.server_name // "(aucun SNI)"),
    (.version // "-"), ((.established // "-")|tostring)] | @tsv' | sort -u

titre "CERTIFICATS (sujet / émetteur) — * = auto-signé"
lire x509 | jq -r 'select(.certificate != null or ."certificate.subject" != null)
  | (.certificate.subject // ."certificate.subject") as $s | (.certificate.issuer // ."certificate.issuer") as $i
  | "\(if $s == $i then "*" else " " end) \($s[0:70])  ←  \($i[0:60])"' | sort -u | head -20

titre "BEACONING — connexions répétées à intervalle régulier (≥ 6 connexions)"
printf "%-15s  %-21s  %5s  %10s  %8s\n" "SOURCE" "DESTINATION" "NB" "INTERVALLE" "ÉCART-T"
lire conn | jq -s -r --arg re "$NON_ROUTABLE" '
  [ .[] | select((."id.resp_h" | test($re)) | not) ]
  | group_by([."id.orig_h", ."id.resp_h", ."id.resp_p"])[]
  | select(length >= 6)
  | (map(.ts) | sort) as $t
  | [ range(1; $t|length) as $k | $t[$k] - $t[$k-1] ] as $d
  | ($d | add / length) as $m
  | ( ($d | map(. - $m | . * .) | add / length) | sqrt ) as $sd
  | [ .[0]."id.orig_h", "\(.[0]."id.resp_h"):\(.[0]."id.resp_p")", length, ($m|floor), ($sd|floor) ]
  | @tsv' | sort -t$'\t' -k3 -rn | head -10 \
  | awk -F'\t' '{printf "%-15s  %-21s  %5s  %9ss  %7ss\n",$1,$2,$3,$4,$5}'
echo "(Un petit écart-type par rapport à l'intervalle moyen = rythme régulier, typique d'un C2.)"

titre "CONNEXIONS LONGUES vers l'extérieur (≥ 10 minutes) — un C2 peut garder une seule connexion ouverte"
printf "%-15s  %-21s  %8s  %12s  %12s  %s\n" "SOURCE" "DESTINATION" "DURÉE" "ENVOYÉ (o)" "REÇU (o)" "PROTOCOLE"
lire conn | jq -r --arg re "$NON_ROUTABLE" '
  select((."id.resp_h" | test($re)) | not) | select((.duration // 0) >= 600)
  | [ ."id.orig_h", "\(."id.resp_h"):\(."id.resp_p")", (.duration|floor),
      (.orig_bytes // 0), (.resp_bytes // 0), (.service // "(aucun reconnu)") ] | @tsv' \
  | sort -t$'\t' -k3 -rn | head -10 \
  | awk -F'\t' '{printf "%-15s  %-21s  %7ss  %12s  %12s  %s\n",$1,$2,$3,$4,$5,$6}'
echo "(Port 443 sans protocole reconnu = trafic qui n'est pas du TLS : à examiner en priorité.)"

titre "DESTINATIONS EXTERNES (nb de connexions / octets envoyés / octets reçus)"
lire conn | jq -s -r --arg re "$NON_ROUTABLE" '
  [ .[] | select((."id.resp_h" | test($re)) | not) ]
  | group_by([."id.resp_h", ."id.resp_p", .proto])[]
  | [ "\(.[0]."id.resp_h"):\(.[0]."id.resp_p")/\(.[0].proto)", length,
      (map(.orig_bytes // 0) | add), (map(.resp_bytes // 0) | add), (.[0].service // "-") ]
  | @tsv' | sort -t$'\t' -k2 -rn | head -15 \
  | awk -F'\t' '{printf "%-28s %5s conn.  envoyé %10s o  reçu %10s o  [%s]\n",$1,$2,$3,$4,$5}'

titre "PROTOCOLES DÉTECTÉS PAR ZEEK (champ service de conn.log)"
lire conn | jq -r '.service // empty' | tr ',' '\n' | sort | uniq -c | sort -rn

titre "POLITIQUE — IRC / SMTP / FTP"
lire irc  | jq -r '"IRC   \(."id.orig_h") → \(."id.resp_h"):\(."id.resp_p")  \(.command // "-") \(.value // "") (nick: \(.nick // "-"))"' | sort -u | head -15
lire smtp | jq -r '"SMTP  \(."id.orig_h") → \(."id.resp_h")  de: \(.mailfrom // "-")  à: \((.rcptto // [])|join(","))  sujet: \(.subject // "-")"' | sort -u | head -15
lire ftp  | jq -r '"FTP   \(."id.orig_h") → \(."id.resp_h")  \(.user // "-")  \(.command // "-") \(.arg // "")"' | sort -u | head -15

titre "NOTICES ZEEK (détections intégrées à Zeek)"
lire notice | jq -r '"\(.note)  —  \((.msg // "")[0:90])"' | sort | uniq -c | sort -rn | head -15

echo -e "\nJournaux analysés : $DIR"
