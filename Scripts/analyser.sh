#!/usr/bin/env bash
# Analyse angry-poutine.pcap avec vos règles et résume les alertes.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
export TZ=UTC
rm -rf sortie && mkdir sortie

suricata -c /etc/suricata/suricata.yaml \
  --include "$PWD/labo.yaml" \
  --set default-rule-path="$PWD/regles" \
  -S regles/labo.rules \
  -r angry-poutine.pcap -k none -l sortie > sortie/console.log 2>&1 || {
    echo "Suricata a échoué. Dernières lignes de sortie/console.log :"
    tail -n 5 sortie/console.log
    exit 1
  }

grep -E '^(E|W):' sortie/console.log || true
echo "--- Alertes par règle ---"
jq -r 'select(.event_type=="alert") | "\(.alert.signature_id)  \(.alert.signature)"' \
  sortie/eve.json | sort | uniq -c | sort -k2n
echo "--- Total : $(jq -c 'select(.event_type=="alert")' sortie/eve.json | wc -l) alerte(s)"
