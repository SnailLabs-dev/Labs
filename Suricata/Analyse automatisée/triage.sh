#!/usr/bin/env bash
# triage.sh — Analyse rapide d'un pcap (malware-traffic-analysis.net) avec Suricata
# Usage : ./triage.sh capture.pcap [regles_supplementaires.rules]
#
# Prérequis dans suricata.yaml (section outputs > eve-log > types) :
#   - dhcp:  { enabled: yes, extended: yes }
#   - files: { force-magic: yes, force-hash: [md5, sha256] }
#   - alert: { payload-printable: yes }      (optionnel)

set -euo pipefail
PCAP="${1:?Usage: $0 capture.pcap [regles.rules]}"
RULES="${2:-triage-mta.rules}"
OUT="sortie_$(basename "${PCAP%.*}")"
EVE="$OUT/eve.json"

mkdir -p "$OUT"
rm -f "$EVE"
# -S remplace les règles du yaml ; utilise -s à la place pour AJOUTER aux règles ET Open
suricata -r "$PCAP" -k none -l "$OUT" -s "$RULES" >/dev/null 2>&1

titre() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"; }

titre "ALERTES (par signature)"
jq -r 'select(.event_type=="alert") | .alert.signature' "$EVE" | sort | uniq -c | sort -rn

titre "HÔTES INTERNES LES PLUS ACTIFS (machine compromise probable)"
jq -r 'select(.event_type=="flow") | .src_ip' "$EVE" \
  | grep -E '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' | sort | uniq -c | sort -rn | head -5

titre "HOSTNAMES — DHCP (IP / MAC / nom)"
jq -r 'select(.event_type=="dhcp" and .dhcp.hostname != null)
       | [(.dhcp.assigned_ip // .dhcp.client_ip // .src_ip), .dhcp.client_mac, .dhcp.hostname] | @tsv' "$EVE" | sort -u

titre "COMPTES — Kerberos (utilisateurs et machines\$)"
jq -r 'select(.event_type=="krb5" and .krb5.cname != null and .krb5.cname != "<empty>")
       | [.src_ip, .krb5.cname, (.krb5.realm // "")] | @tsv' "$EVE" | sort -u

titre "COMPTES — SMB/NTLM (IP / domaine / utilisateur / hostname)"
jq -r 'select(.event_type=="smb" and .smb.ntlmssp != null)
       | [.src_ip, .smb.ntlmssp.domain, .smb.ntlmssp.user, .smb.ntlmssp.host] | @tsv' "$EVE" | sort -u

titre "FICHIERS TRANSFÉRÉS (type / taille / SHA256 / origine)"
jq -r 'select(.event_type=="fileinfo")
       | [(.fileinfo.magic // "?")[0:40], (.fileinfo.size|tostring), (.fileinfo.sha256 // "-"),
          ((.http.hostname // .dest_ip) + (.http.url // ""))] | @tsv' "$EVE" | sort -u

titre "DOMAINES DNS DEMANDÉS"
jq -r 'select(.event_type=="dns") | (.dns.rrname // .dns.queries[0].rrname // empty)' "$EVE" \
  | sort | uniq -c | sort -rn | head -30

titre "HTTP (hôte / méthode / URL / User-Agent)"
jq -r 'select(.event_type=="http")
       | [.dest_ip, .http.hostname, .http.http_method, .http.url[0:80], (.http.http_user_agent // "-")[0:50]] | @tsv' "$EVE" | sort -u | head -40

titre "TLS (SNI / sujet du certificat / JA3)"
jq -r 'select(.event_type=="tls")
       | [.dest_ip, (.dest_port|tostring), (.tls.sni // "(aucun SNI)"), (.tls.subject // "-")[0:60], (.tls.ja3.hash // "-")] | @tsv' "$EVE" | sort -u

titre "DESTINATIONS EXTERNES (IP:port, nb de flux) — pour repérer le C2"
jq -r 'select(.event_type=="flow") | "\(.dest_ip):\(.dest_port)/\(.proto)"' "$EVE" \
  | grep -vE '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|224\.|239\.|255\.)' | sort | uniq -c | sort -rn | head -15

echo -e "\nRésultats complets : $EVE"
