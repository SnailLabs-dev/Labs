# Labo — Analyse d'un pcap malveillant avec Security Onion

> Cours de surveillance préventive en cybersécurité — Cégep de l'Outaouais
> Durée : 2 cours de 3 heures · Plateforme : Security Onion 3.4.0 (une instance par étudiant)

## 🎯 Objectifs

À la fin de ces deux cours, tu seras capable de :

- importer un pcap dans Security Onion et retrouver ses données dans la console (SOC);
- utiliser les vues **Alerts**, **Hunt**, **Dashboards**, **PCAP** et **Cases** pour mener une analyse;
- mettre à jour les règles Suricata et importer tes propres règles;
- faire le triage d'une infection à partir des journaux **Zeek**;
- écrire et déployer une règle **YARA** (fichiers) et une règle **Sigma** (journaux).

## 📁 Contenu du dossier

| Fichier | Rôle |
|---|---|
| `triage-zeek.sh` | Script de triage à partir des journaux Zeek (équivalent du `triage.sh` du labo Suricata) |
| `yara/snaillabs.yar` | Trois règles YARA d'introduction |
| `yara/creer-echantillons.sh` | Crée des échantillons **inoffensifs** pour tester les règles YARA |
| `sigma/*.yml` | Trois règles Sigma sur les journaux Zeek (DNS, HTTP, DHCP) |

Tu auras aussi besoin de `triage-mta.rules`, qui se trouve dans le dossier `suricata-triage` du labo précédent.

## 🕵️ Le scénario

Tu es analyste au centre des opérations de sécurité (SOC) de **NatureForce**. Le **1er octobre 2026, vers 15 h 30 (heure de l'Est)**, des alertes sont signalées pour un poste du réseau interne. On a récupéré une capture du trafic de ce poste. À toi de comprendre ce qui s'est passé.

**Réseau local (LAN)**

| Élément | Valeur |
|---|---|
| Plage d'adresses | `10.10.1.0/24` |
| Domaine | `natureforce.com` (NetBIOS : `NATUREFORCE`) |
| Contrôleur de domaine | `10.10.1.10` — `WIN-LEKBU2OY51N` |
| Passerelle | `10.10.1.1` |

**Fichier :** `2026-10-01-traffic-analysis-exercise.pcap` (36 Mo), tiré de l'exercice du 2026-10-01 de [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/).

## 🧭 Avant de commencer : rappels importants

> ⚠️ Le pcap contient de **vrais** maliciels. Travaille uniquement dans le cyber range. N'ouvre jamais un fichier extrait du trafic.

- **Les événements gardent leur heure d'origine.** Security Onion conserve l'horodatage d'origine des paquets. Si une vue est vide, élargis la période dans le sélecteur de temps (en haut à droite) pour couvrir la date de la capture.
- **Les règles s'appliquent aux imports suivants.** Une règle ajoutée après l'import ne s'applique pas rétroactivement : il faut réimporter le pcap (voir la partie 6).
- **Note tes requêtes.** Pour chaque réponse, écris la vue et la requête utilisées. C'est ce qui sera évalué.

---

# 📘 COURS 1 — Explorer une infection dans Security Onion

## Partie 1 — Importer le pcap (15 min)

1. Récupère l'archive fournie par ton enseignant sur ta VM Kali, puis extrais le pcap (le mot de passe t'est donné en classe) :
   ```bash
   7z x 2026-10-01-traffic-analysis-exercise_pcap.zip
   ```
2. Copie le pcap sur ta VM Security Onion :
   ```bash
   scp 2026-10-01-traffic-analysis-exercise.pcap <utilisateur>@<ip_security_onion>:/tmp/
   ```
3. Connecte-toi en SSH à Security Onion et importe le pcap :
   ```bash
   sudo so-import-pcap /tmp/2026-10-01-traffic-analysis-exercise.pcap
   ```
   > 💡 **Pourquoi pas la page Grid?** Le téléversement par la console est limité à 25 Mo par défaut. Ce pcap fait 36 Mo : il faut passer par `so-import-pcap`, qui n'a pas cette limite.
4. La commande affiche un **lien** vers les résultats. Ouvre-le : il règle déjà la période et le filtre sur ce pcap.
5. Note le **hash MD5** affiché par la commande. Il identifie ton import dans `/nsm/import/`.

**✅ À remettre :** le hash MD5 du pcap et la période couverte par la capture (date et heures).

## Partie 2 — Alerts : qu'est-ce qui a sonné? (25 min)

La vue **Alerts** regroupe les alertes de Suricata (réseau), de Strelka/YARA (fichiers) et d'ElastAlert/Sigma (journaux).

1. Ouvre **Alerts**. Les alertes sont regroupées par règle, avec un compteur.
2. Classe-les par **sévérité**. Quelles sont les trois alertes les plus graves?
3. Clique sur une alerte, puis développe un événement. Repère :
   - `source.ip` et `destination.ip` (qui parle à qui);
   - `rule.name` (le nom de la règle);
   - le champ `network.community_id`.
4. Ouvre les détails de la règle (*Tune Detection*). Lis la signature Suricata : sur quoi se déclenche-t-elle?

**✅ À remettre :**

| Question | Réponse | Comment je l'ai trouvé |
|---|---|---|
| Combien de règles différentes ont déclenché? | | |
| Quelle IP interne revient le plus souvent? | | |
| Quelle alerte te semble la plus révélatrice de l'infection? Pourquoi? | | |

## Partie 3 — Hunt : répondre aux questions de l'enquête (60 min)

**Hunt** permet d'interroger tous les journaux (Suricata, Zeek, Strelka). La syntaxe : `champ:valeur`, puis `| groupby champ1 champ2` pour regrouper.

Commence par cette requête pour voir quels journaux existent pour ton import :

```
* | groupby event.dataset
```

Pour chaque question, voici une requête de départ. **Adapte-la** : l'objectif est que tu comprennes ce que tu cherches.

| # | Question | Requête de départ |
|---|---|---|
| 1 | IP de la machine infectée | `event.dataset:zeek.conn \| groupby source.ip` |
| 2 | Adresse MAC et hostname | `event.dataset:zeek.dhcp \| groupby host.hostname host.mac dhcp.assigned_ip` |
| 3 | Nom d'utilisateur | `event.dataset:zeek.kerberos \| groupby kerberos.client` |
| 3b | (autre source) | `event.dataset:zeek.ntlm \| groupby user.name host.name host.domain` |
| 4 | Domaines contactés | `event.dataset:zeek.dns \| groupby dns.query.name` |
| 5 | Fichiers téléchargés | `event.dataset:zeek.files \| groupby file.mime_type file.source hash.md5` |
| 6 | Requêtes HTTP | `event.dataset:zeek.http \| groupby http.virtual_host http.uri http.useragent` |
| 7 | Connexions TLS | `event.dataset:zeek.ssl \| groupby ssl.server_name destination.ip` |
| 8 | Analyse des fichiers par Strelka | `event.module:strelka \| groupby file.mime_type hash.sha256` |
| 9 | Connexions vers le port 443 et protocole reconnu par Zeek | `event.dataset:zeek.conn AND destination.port:443 \| groupby destination.ip network.protocol` |
| 10 | Le même fichier vu par Suricata | `event.dataset:suricata.fileinfo \| groupby file.name file.size hash.sha256` |

> 💡 **Astuce :** si un champ n'existe pas, clique sur un événement pour voir la liste des champs réellement disponibles. Les noms peuvent varier un peu d'une version à l'autre.

**✅ À remettre :**

| Question | Réponse | Vue + requête |
|---|---|---|
| IP de la machine infectée | | |
| Adresse MAC | | |
| Hostname | | |
| Nom d'utilisateur | | |
| Domaines visités juste avant l'infection (chaîne d'infection) | | |
| Outil utilisé pour télécharger les fichiers (User-Agent) | | |
| Fichier malveillant téléchargé (URL complète, type) | | |
| Hash SHA256 du fichier (selon Strelka) | | |
| Adresse IP et port du C2 | | |
| Pourquoi le trafic du C2 est-il suspect, même sur le port 443? | | |
| Le hash du fichier selon **Suricata** est-il le même que selon **Strelka**? Compare aussi la taille. Comment l'expliques-tu? | | |

> 💡 **Indice pour le C2 :** cherche une connexion vers l'extérieur qui dure longtemps et qui reçoit beaucoup de données. Quel protocole Zeek y a-t-il reconnu?

## Partie 4 — Dashboards et PCAP : voir et confirmer (30 min)

1. Ouvre **Dashboards**. Contrairement à Hunt, chaque champ y a son propre tableau. Repère d'un coup d'œil les principales IP de destination et les protocoles.
2. Dans Hunt ou Alerts, choisis l'événement qui correspond au **téléchargement du fichier malveillant**. Dans le menu de l'événement, choisis **PCAP** : Security Onion reconstruit la session complète.
3. Dans la vue PCAP, examine la requête HTTP et le début de la réponse. Reconnais-tu l'en-tête du fichier (`MZ`, `PK`…)?
4. Reviens à l'alerte Suricata de la partie 2. Copie son `network.community_id` et cherche-le dans Hunt :
   ```
   network.community_id:"<valeur>"
   ```
   Quels journaux Zeek décrivent **la même connexion**?

**✅ À remettre :** une capture d'écran de la vue PCAP du téléchargement, et la liste des `event.dataset` trouvés avec le Community ID.

## Partie 5 — Cases : documenter l'incident (20 min)

1. Dans **Cases**, crée un dossier nommé `Infection <hostname> — <date>`.
2. Depuis Alerts ou Hunt, ajoute au dossier (menu de l'événement → *Add to Case*) :
   - l'alerte la plus révélatrice;
   - l'événement du téléchargement;
   - un événement montrant le C2.
3. Dans l'onglet des observables, ajoute l'IP de la victime, l'IP ou le domaine du C2 et le hash du fichier.
4. Rédige un résumé de 5 lignes : quoi, qui, quand, comment, et recommandation.

**✅ À remettre :** une capture d'écran du dossier.

---

# 📗 COURS 2 — Règles et détection : Suricata, Zeek, YARA, Sigma

Toutes les règles se gèrent dans **Detections** :

| Moteur | Analyse | Langage de règle |
|---|---|---|
| Suricata | Le trafic réseau | NIDS (règles Suricata) |
| Strelka | Les fichiers extraits du trafic | YARA |
| ElastAlert | Les journaux déjà indexés | Sigma |

## Partie 6 — Gérer les règles Suricata (40 min)

### 6.1 Mettre à jour les règles ET Open

1. Ouvre **Detections**, puis le menu **Options**.
2. Choisis **Suricata**, puis clique sur **FULL UPDATE**.
3. Pendant la mise à jour, cherche dans Detections combien de règles contiennent `ET MALWARE` dans leur nom. Combien sont actives?

> Par défaut, Security Onion vérifie les nouvelles règles toutes les 24 heures. Le **FULL UPDATE** force une synchronisation immédiate.

### 6.2 Ajouter une règle à la main

1. Dans **Detections**, clique sur le bouton bleu **+**, entre **Options** et la barre de requête.
2. Langage : **Suricata**.
3. Écris une règle qui détecte la requête DNS vers le domaine de la **page d'appât** que tu as trouvé au cours 1 (le domaine contacté juste après le site visité) :
   ```
   alert dns $HOME_NET any -> any any (msg:"SNAILLABS IOC - <domaine>"; dns.query; content:"<domaine>"; nocase; endswith; sid:1300001; rev:1;)
   ```
4. Clique sur **CREATE**. La règle est déployée en quelques minutes.

### 6.3 Importer un fichier de règles (règles locales)

Pour importer plusieurs règles d'un coup, on les dépose dans le dossier des règles locales :

```bash
sudo cp triage-mta.rules /nsm/rules/custom-local-repos/local-Suricata/
```

Retourne ensuite dans **Detections → Options → Suricata → FULL UPDATE**, puis cherche `TRIAGE` dans Detections.

> ⚠️ Tant que le fichier reste dans ce dossier, chaque synchronisation le réimporte. Une modification faite dans l'interface web peut donc être écrasée.

### 6.4 Réimporter le pcap pour tester

Security Onion refuse de réimporter un pcap déjà traité. Il faut d'abord supprimer son dossier :

```bash
sudo rm -rf /nsm/import/<md5_du_pcap>
sudo so-import-pcap /tmp/2026-10-01-traffic-analysis-exercise.pcap
```

### 6.5 Ajuster une règle bruyante

Choisis une alerte qui sonne trop souvent. Dans le détail de la règle, onglet **Tuning**, bouton **+**, ajoute un **Threshold** (`limit`, `by_src`, count 1, 3600 secondes).

### 6.6 Défi : une règle de comportement

Une règle sur un domaine ou une URL précise ne détecte **que cette infection-ci**. Écris maintenant une règle qui détecterait le même **comportement** avec une autre infection. Choisis l'une des deux :

- **A.** `curl` qui télécharge un fichier `.exe` depuis une **adresse IP** plutôt qu'un nom de domaine (indices : `http.user_agent`, `http.host`, `http.uri`, `pcre`);
- **B.** du trafic vers le **port 443** qui n'est **pas du TLS** (indice : le mot-clé `app-layer-protocol` accepte la valeur `failed`, quand Suricata ne reconnaît aucun protocole).

Vérifie qu'elle ne déclenche qu'**une seule fois** sur le pcap, au bon endroit. Sinon, ajoute un `threshold`.

**✅ À remettre :**

| Question | Réponse |
|---|---|
| Ta règle 6.2 a-t-elle déclenché après la réimportation? (capture d'écran) | |
| Ta règle 6.6 (texte de la règle + capture de l'alerte) | |
| Quelles règles `TRIAGE` ont déclenché? | |
| Qu'apportent les règles `TRIAGE` par rapport aux règles ET Open? | |

## Partie 7 — Triage avec Zeek (30 min)

Zeek ne génère pas d'alertes, mais des **journaux** pour chaque protocole. Le script `triage-zeek.sh` produit, à partir de ces journaux, le même rapport que `triage.sh` produisait avec Suricata.

1. Copie le script sur Security Onion, puis lance-le sur le dossier de ton import :
   ```bash
   chmod +x triage-zeek.sh
   sudo ./triage-zeek.sh /nsm/import/<md5_du_pcap>
   ```
2. Lis le rapport section par section.

**✅ À remettre :**

| Question | Réponse |
|---|---|
| Quelles réponses du cours 1 retrouves-tu dans le rapport? | |
| Que montre la section **CONNEXIONS LONGUES**? Quelle connexion te semble suspecte et pourquoi? | |
| La section **BEACONING** détecte-t-elle ce C2? Pourquoi? (indice : combien de connexions le C2 a-t-il ouvertes?) | |
| Nomme une information que Zeek donne et que Suricata ne donnait pas (ou difficilement) | |
| Nomme une information que Suricata donne et que Zeek ne donne pas | |

> 💡 Zeek **décrit** tout le trafic sans jugement : c'est un enregistreur. Suricata **juge** le trafic selon ses règles : c'est un détecteur. Security Onion combine les deux.

## Partie 8 — Introduction à YARA (40 min)

YARA décrit des **fichiers** à l'aide de chaînes (`strings`) et d'une condition. Dans Security Onion, Strelka applique les règles YARA aux fichiers extraits du trafic.

### 8.1 Lire une règle

Ouvre `yara/snaillabs.yar`. Pour chacune des trois règles, explique en une phrase ce qu'elle détecte et le rôle de sa condition.

### 8.2 Tester sur ta VM Kali

```bash
sudo apt install -y yara
cd yara
./creer-echantillons.sh                 # crée des fichiers INOFFENSIFS dans echantillons/
yara snaillabs.yar echantillons/        # quels fichiers sont détectés?
yara -s snaillabs.yar echantillons/     # -s affiche les chaînes trouvées
```

Les fichiers `note.txt` et `admin_legitime.ps1.txt` ne doivent **pas** être détectés. Vérifie-le.

### 8.3 Étudier l'exécutable sans y toucher

Strelka a déjà analysé l'exécutable téléchargé dans le pcap. Dans **Hunt**, retrouve son analyse :

```
event.module:strelka AND file.mime_type:*dosexec*
```

Ouvre l'événement et explore les champs `scan.pe.*`. Note :

- les informations de version (éditeur, description, nom de fichier d'origine);
- la date de compilation : est-elle plausible?
- les sections du fichier et leur taille : laquelle est anormalement grosse?
- la présence ou non d'une signature numérique.

> 💡 Si le type MIME est différent dans ton instance, cherche plutôt le hash SHA256 trouvé au cours 1 : `hash.sha256:<valeur>`.

### 8.4 Écrire ta propre règle

Écris une règle `Mon_Faux_Service` qui détecte cet exécutable **par ses caractéristiques**, et non par son hash. Utilise le module `pe` de YARA :

```
import "pe"

rule Mon_Faux_Service
{
    condition:
        uint16(0) == 0x5A4D
        and pe.version_info["CompanyName"] == "..."
        and ...
}
```

Pistes : `pe.version_info["..."]`, `pe.number_of_signatures`, `pe.timestamp`, `pe.sections`. Explique dans un commentaire pourquoi ta règle détecterait aussi une **variante** de ce fichier (autre nom, autre hash).

> 🧪 **Test local (facultatif, dans le cyber range seulement) :** dans Wireshark, *Fichier → Exporter des objets → HTTP* permet d'extraire l'exécutable sur ta VM Kali pour le tester avec `yara -s`. C'est un exécutable Windows : il ne peut pas s'exécuter sur Kali, mais **ne le copie jamais hors du cyber range**.

### 8.5 Déployer dans Security Onion

1. **Detections** → **+** → Langage **YARA**.
2. Colle ta règle, puis clique sur **CREATE**.
3. Réimporte le pcap (voir 6.4). Attention : Strelka n'analyse pas deux fois le même fichier pendant **48 heures**. Si le premier import date de moins de 48 heures, utilise le deuxième pcap fourni par ton enseignant.
4. Cherche l'alerte dans **Alerts**.

**✅ À remettre :** tes observations de 8.3, ta règle `Mon_Faux_Service` commentée, et une capture de l'alerte YARA dans Security Onion (ou la sortie de `yara -s`).

## Partie 9 — Introduction à Sigma (40 min)

Sigma est à la **journalisation** ce que Suricata est au trafic et YARA aux fichiers. On décrit les événements à détecter en YAML, puis l'outil convertit la règle dans le langage du SIEM.

### 9.1 Lire une règle

Ouvre `sigma/zeek_dns_verification_ip_publique.yml` et repère :

- `logsource` : sur quels journaux porte la règle;
- `detection` : les sélections et la `condition`;
- `level` et `falsepositives`.

### 9.2 Déployer dans Security Onion

1. **Detections** → **+** → Langage **Sigma - Single event**.
2. Colle la règle, puis clique sur **CREATE**.
3. Ouvre la règle, onglet **Detection Source**, bouton **Convert** : c'est la requête réellement envoyée à Elasticsearch. Compare-la avec la règle YAML.

> ⚠️ **Pourquoi une règle Sigma ne sonne-t-elle pas sur un pcap importé?** Par défaut, ElastAlert cherche les événements récents selon leur **horodatage d'origine**. Or un pcap importé contient des événements datés du jour de la capture. Ton enseignant t'indiquera si ton instance est configurée pour évaluer les événements selon leur **heure d'arrivée** (option `useEsql`). Sinon, valide ta règle avec la requête convertie dans **Hunt**.

### 9.3 Valider dans Hunt

Copie la condition de la requête convertie et exécute-la dans **Hunt**. Par exemple :

```
event.dataset:zeek.dns AND dns.query.name:*ipify.org
```

### 9.4 Écrire ta propre règle

Dans ce pcap, l'exécutable a été téléchargé avec **curl**. Écris une règle Sigma qui détecte, dans les journaux `zeek.http`, une requête faite avec `curl` vers une URI qui se termine par `.exe`.

- Indices : les champs sont `http.useragent` et `http.uri`; les modificateurs s'appellent `|startswith` et `|endswith`.
- Vérifie la conversion dans Detections, puis valide la requête dans Hunt sur ton pcap.

**Bonus :** écris une deuxième règle sur les journaux `zeek.conn` qui détecte une connexion vers le port 443 pour laquelle Zeek n'a reconnu **aucun** protocole (indice : `network.protocol: null`).

**✅ À remettre :** ta règle Sigma, la requête convertie, et le résultat de la requête dans Hunt.

---

## 🧾 Synthèse (à faire à la fin du cours 2)

Remplis ce tableau en une ligne par case :

| | Suricata | Zeek | YARA (Strelka) | Sigma (ElastAlert) |
|---|---|---|---|---|
| Qu'est-ce qui est analysé? | | | | |
| Produit des alertes ou des journaux? | | | | |
| Un exemple trouvé dans ce labo | | | | |

## 🛠️ Dépannage

| Symptôme | Cause probable |
|---|---|
| Vue vide dans Alerts ou Hunt | Période trop courte : élargis-la pour couvrir la date de la capture |
| « already imported » | Supprime `/nsm/import/<md5>` avant de réimporter |
| Nouvelle règle Suricata sans alerte | Pas de réimportation, ou la règle n'est pas encore déployée (attends quelques minutes ou fais un FULL UPDATE) |
| Règle YARA sans alerte | Fichier déjà analysé par Strelka dans les dernières 48 h : utilise un autre pcap |
| Règle Sigma sans alerte | Les événements importés sont « vieux » : valide la requête dans Hunt (voir 9.2) |
| `triage-zeek.sh` : « Aucun conn.log » | Mauvais dossier : vérifie avec `sudo find /nsm/import -name 'conn*'` |

---

*SnailLabs — exercices de cybersécurité pour les faiseurs.* 🐌
