# ThreatLens — Rapport de Projet

**Type de projet :** Projet de fin d'année (PFA)
**Auteur :** [Votre nom]
**Encadrant(e) :** [Nom du superviseur]
**Date :** 11 août 2026
**État d'avancement :** En cours — le moteur d'intelligence et la plateforme web sont fonctionnels ; les modules de reporting et de durcissement sont planifiés.

---

## 1. Résumé exécutif

ThreatLens est une plateforme **passive de renseignement en sources ouvertes (OSINT)** qui évalue le risque de toute **adresse IP ou de tout nom de domaine** public et produit un rapport structuré et actionnable.

L'utilisateur saisit une cible (par exemple `8.8.8.8` ou `github.com`). La plateforme collecte automatiquement des données publiques sur cette cible auprès de **cinq sources indépendantes**, corrèle les faits en **constats de sécurité (findings)**, calcule un **score de risque (0–100)** et distingue en outre **deux profils de risque** :

- **Exposition (Exposure)** — la facilité avec laquelle *cette cible* pourrait être compromise par d'autres (ports ouverts, vulnérabilités connues).
- **Menace (Threat)** — le danger que *cette cible* représente pour les autres (réputation malveillante).

Tout le renseignement est **passif** : la plateforme n'envoie jamais de paquets vers la cible. Elle s'appuie exclusivement sur des données déjà collectées par des services publics de scan et de réputation, ce qui rend chaque analyse entièrement légale et démontrable.

---

## 2. Motivation et problème traité

Les organisations et les analystes sécurité ont régulièrement besoin d'une réponse rapide à deux questions concernant un actif exposé sur Internet :

1. *« Cette IP/ce domaine est-il dangereux ? »* (par exemple une IP suspecte ayant attaqué le réseau).
2. *« Notre propre infrastructure est-elle exposée ? »* (par exemple un serveur public qui pourrait être compromis).

Ces réponses sont dispersées dans de nombreux services indépendants : scanneurs de réseau, bases de vulnérabilités, moteurs de réputation antivirus, services de géolocalisation et d'enregistrement de domaines. Chaque source répond à **une seule question précise**, et aucune n'est concluante à elle seule.

**Problème traité :** aucun outil public unique n'agrège, ne recoupe et ne score tous ces signaux dans un verdict unique et lisible. ThreatLens comble cette lacune grâce à un **moteur de corrélation** qui combine les faits issus de différentes sources et en déduit des conclusions qu'aucune source unique ne fournit.

---

## 3. Objectifs

1. Construire une plateforme web permettant de scanner toute IP ou tout domaine en un clic.
2. Agréger du renseignement public à partir de **cinq sources de données indépendantes**.
3. Implémenter un **moteur de corrélation maison** qui transforme les faits bruts en constats avec sévérité, explication et recommandations.
4. Implémenter un **modèle de scoring** (0–100, avec les niveaux LOW/MEDIUM/HIGH/CRITICAL) transparent et non faussé par des signaux mineurs.
5. Distinguer les profils **Exposition vs Menace** pour que le rapport réponde à « est-ce une victime ou un danger ? ».
6. Persister tous les scans dans une base de données pour **l'historique et le reporting**.
7. Fournir des comptes utilisateurs, des clés API par utilisateur, des thèmes et des paramètres.

---

## 4. Pile technologique

| Composant | Technologie | Rôle |
|---|---|---|
| Langage | Python 3.13 | Tout le backend et le moteur d'intelligence |
| Framework web | Flask 3.1.3 | Application web et routes |
| Base de données | SQLite + SQLAlchemy (ORM) | Persistance des utilisateurs et des scans |
| Authentification | Flask-Login + Flask-Bcrypt | Sessions et hachage des mots de passe |
| Client HTTP | requests | Tous les appels API externes |
| Analyse de certificats | cryptography 50.0.0 | Décodage des certificats TLS au format DER |
| Frontend | Templates Jinja2 + Tailwind CSS (CDN) + Font Awesome | Styles UI et icônes |
| Tests | unittest (bibliothèque standard Python) | Tests unitaires du moteur de corrélation |
| Configuration | python-dotenv + `.env` | Gestion des secrets (clés API) |
| Reporting (planifié) | ReportLab 4.1.0 | Génération de rapports PDF (installé, non encore branché) |

Toutes les dépendances sont listées dans `requirements.txt`.

---

## 5. Architecture

Le projet suit l'**architecture en 5 couches** définie dans le cahier des charges.

| Couche | Responsabilité | Implémentation |
|---|---|---|
| **1. Présentation** | Interface utilisateur et pages | `templates/*.html`, `static/style.css` |
| **2. Couche API** | Communication avec les services externes | `apis/shodan_api.py`, `apis/nvd_api.py`, `apis/virustotal_api.py`, `apis/ipapi.py`, `apis/metadata_api.py` |
| **3. Corrélation** | Logique d'analyse maison (le cœur) | `engine/correlator.py`, `engine/scorer.py` |
| **4. Données** | Persistance des utilisateurs et de l'historique | `models.py` + base SQLite (`instance/threatlens.db`) |
| **5. Reporting** | Génération des rapports (PDF) | **Planifié** — ReportLab installé, pas encore branché |

### Structure des fichiers

```
ThreatLens/
├── main.py                    # Application Flask, routes, migrations
├── config.py                  # Lit le .env (clé secrète, clés API)
├── models.py                  # Modèles de base de données User et ScanResult
├── requirements.txt           # Dépendances Python
├── .env / .env.example        # Clés API & secrets (jamais versionnés)
├── apis/                      # Couche 2 — sources de données externes
│   ├── shodan_api.py          # API officielle Shodan + repli gratuit InternetDB
│   ├── nvd_api.py             # Recherches CVE NVD/NIST (ID exact)
│   ├── virustotal_api.py      # Réputation VirusTotal (IP ou domaine)
│   ├── ipapi.py               # Géolocalisation ip-api (gratuit, sans clé)
│   └── metadata_api.py        # Enregistrement de domaine RDAP + certificat TLS
├── engine/                    # Couche 3 — le cœur
│   ├── correlator.py          # Règles ThreatCorrelator + pipeline analyze_target()
│   └── scorer.py              # Score de risque + profils Exposition/Menace
├── templates/                 # Couche 1 — pages
│   ├── base.html              # Layout, navigation, messages flash
│   ├── index.html             # Tableau de bord : formulaire de scan + scans récents
│   ├── login.html / register.html
│   ├── settings.html          # Paramètres visuels, sécurité, intelligence, alertes
│   ├── history.html           # Tous les scans du compte
│   ├── control_panel.html     # Admin : gestion des utilisateurs
│   └── target_details.html    # Rapport d'intelligence complet d'un scan
├── static/style.css           # Styles personnalisés
├── test/test_correclator.py   # Tests unitaires
└── instance/threatlens.db     # Base de données SQLite (auto-créée)
```

---

## 6. Les cinq sources de données

Chaque source répond à **une question précise**. Elles se complètent ; aucune ne suffit à elle seule.

| # | Source | Question répondue | Exemple de données | Clé requise |
|---|---|---|---|---|
| 1 | **ip-api** (géolocalisation) | « Où se trouve cette machine et qui l'héberge ? » | pays, ville, FAI, organisation, GPS | Non |
| 2 | **Shodan** (infrastructure) | « Qu'est-ce qui est exposé sur son réseau ? » | ports ouverts, noms d'hôtes, OS, organisation, CVE détectées | Optionnelle (repli InternetDB gratuit) |
| 3 | **NVD / NIST** (vulnérabilités) | « À quel point les failles connues sont-elles dangereuses ? » | ID CVE, score CVSS (0–10), sévérité, description | Non |
| 4 | **VirusTotal** (réputation) | « Que pensent ~70 moteurs antivirus ? » | compteurs malicious / suspicious / harmless / undetected | Oui (optionnelle) |
| 5 | **RDAP** (enregistrement de domaine) | « Qui possède le domaine et quel âge a-t-il ? » | registraire, date de création, date d'expiration | Non |
| — | **SSL/TLS** (local) | « Quel certificat TLS présente-t-il ? » | émetteur, sujet, expiration (jours restants) | Non (fait localement via socket Python + cryptography) |

### Détails des sources

**1. Géolocalisation — ip-api.com** (`apis/ipapi.py`)
Gratuit, sans clé. Retourne la localisation physique et l'organisation d'hébergement de l'IP. Permet de comprendre le contexte d'hébergement (fournisseur cloud vs FAI résidentiel).

**2. Infrastructure et ports — Shodan** (`apis/shodan_api.py`)
Shodan est le « moteur de recherche des appareils connectés à Internet » ; il a déjà scanné tout Internet, si bien que ses données sont utilisées **sans toucher la cible** (analyse passive).

Deux modes, par ordre de priorité :
- **API REST officielle** (`api.shodan.io`) — utilisée lorsqu'une clé API est configurée. Retourne les ports ouverts, noms d'hôtes, OS, organisation et une table `vulns` d'**ID CVE avec de vrais scores CVSS**. Le vrai score CVSS est parsé et converti en sévérité.
- **Repli gratuit InternetDB** (`internetdb.shodan.io`) — sans clé. Retourne les ports ouverts et des ID CVE **sans score** ; le moteur résout alors chaque ID exact auprès de NVD pour obtenir de vrais scores.

**3. Scores de vulnérabilité — NVD/NIST** (`apis/nvd_api.py`)
Base de données officielle américaine des vulnérabilités. `get_cve_by_id()` récupère une CVE unique par son **identifiant exact** (paramètre `cveId`). Retourne le score CVSS de base et la sévérité. La recherche par ID exact garantit l'absence de résultats hors sujet.
- Une fonction de recherche par mots-clés existe (`get_nvd_vulnerabilities`) mais **n'est pas utilisée dans le flux de scan par défaut** : un mot-clé générique comme « linux » renvoie des CVE hors sujet et gonfle le score de risque. C'est une décision d'ingénierie délibérée.

**4. Réputation — VirusTotal** (`apis/virustotal_api.py` et en ligne dans `engine/correlator.py`)
VirusTotal agrège les verdicts d'environ 70 moteurs antivirus. Le moteur lit `last_analysis_stats` et compte les moteurs `malicious` / `suspicious` / `harmless` / `undetected`. Fonctionne pour les IP comme pour les domaines. Sans clé, il renvoie des zéros plutôt que de fabriquer des détections.

**5. Enregistrement de domaine — RDAP** (`apis/metadata_api.py`)
RDAP (Registration Data Access Protocol) est le successeur moderne et gratuit du WHOIS. Le moteur interroge `rdap.org`, qui route automatiquement vers le registre adéquat selon l'extension du domaine, et en extrait le **registraire**, la **date de création** et la **date d'expiration**. Les adresses IP n'ayant pas d'enregistrement de domaine, elles renvoient correctement N/A. (Un module WHOIS existait auparavant comme simple placeholder renvoyant des chaînes codées en dur ; il a été remplacé par de vraies recherches RDAP.)

**6. Certificat TLS — local** (`apis/metadata_api.py`)
Se connecte à la cible sur le port 443, effectue une poignée de main TLS avec SNI et lit le certificat. Utilise `ssl` pour la poignée de main et la bibliothèque `cryptography` pour décoder le certificat DER brut (voir section 12, correctif n°11).

---

## 7. Le flux de scan (de bout en bout)

Un scan est déclenché par `POST /scan` et exécuté par `analyze_target()` dans `engine/correlator.py` :

1. **Résolution** — `socket.gethostbyname()` convertit un domaine en IP (une IP brute est utilisée telle quelle).
2. **Géolocalisation** — ip-api retourne la localisation physique et l'hébergeur.
3. **Shodan** — l'API officielle (si clé) ou InternetDB gratuit retourne ports ouverts, noms d'hôtes, OS et ID CVE détectés.
4. **Enrichissement NVD** — chaque ID CVE sans score est résolu par ID exact pour obtenir son vrai score CVSS et sa sévérité.
5. **VirusTotal** — compteurs de réputation (zéro si pas de clé).
6. **Corrélation** — `ThreatCorrelator` applique les règles et produit les constats.
7. **Scoring** — `calculate_score()` calcule le score de risque 0–100.
8. **Profils** — `calculate_profiles()` calcule les indices Exposition et Menace plus le verdict.
9. **Métadonnées** — RDAP (enregistrement de domaine) et certificat TLS.
10. **Persistance** — tout le résultat est stocké dans la base SQLite.
11. **Affichage** — redirection vers la page de rapport.

Chaque appel externe est encapsulé dans `try/except` avec des timeouts courts ; une source en échec renvoie des valeurs par défaut sûres (N/A ou 0) pour qu'un scan **ne plante jamais** parce qu'un service est en panne ou limité.

---

## 8. Le moteur de corrélation (`engine/correlator.py`)

C'est la **« pièce maîtresse »** du projet — la logique originale qui transforme les faits bruts en conclusions. Chaque constat porte : **titre, sévérité, description, recommandation et catégorie** (`exposure` ou `threat`).

### 8.1 Règles sur les ports (données Shodan)

| Condition | Constat | Sévérité | Catégorie |
|---|---|---|---|
| Port 3389 ouvert | RDP Exposé Publiquement | HIGH | exposure |
| Port 22 ouvert | SSH Exposé Publiquement | MEDIUM | exposure |
| Ports 1433 / 3306 / 5432 ouverts | Base de Données Exposée Publiquement | CRITICAL | exposure |
| Port 23 ouvert | Telnet Non Chiffré | HIGH | exposure |
| Port 21 ouvert | FTP Non Chiffré | MEDIUM | exposure |
| Plus de 20 ports ouverts | Surface d'Attaque Critiquement Étendue | CRITICAL | exposure |

### 8.2 Règles CVE (données NVD/Shodan)

- Toute CVE avec CVSS ≥ 9,0 → **Vulnérabilité(s) Critique(s) Décelée(s)** (CRITICAL, exposure), listant les CVE.
- Sinon, les CVE de sévérité élevée → **Vulnérabilités Élevées Non Corrigées** (HIGH, exposure).
- Plus de 5 CVE → **Surface d'Attaque Vulnérable Étendue** (HIGH, exposure).

### 8.3 Règles de réputation (données VirusTotal)

Des **tranches de sévérité**, et non un constat par moteur antivirus (c'était un correctif du bug de scoring) :
- ≥ 6 moteurs malveillants → **Réputation Malveillante Confirmée** (CRITICAL, threat).
- 1 à 5 moteurs malveillants → **Réputation Suspecte** (MEDIUM, threat).

### 8.4 Règles de corrélation croisée (l'élément différenciant)

Ces règles combinent des faits issus de **sources différentes** — la véritable « corrélation » qui rend le projet original :

| Condition | Constat | Sévérité | Catégorie | Raisonnement |
|---|---|---|---|---|
| RDP ouvert (Shodan) **+** CVE critique (NVD) | Intrusion Distante Potentielle | CRITICAL | exposure | « La porte du bureau à distance est ouverte **et** elle a une faille critique connue » |
| Réputation malveillante (VT) **+** port de base de données ouvert (Shodan) | Exfiltration de Données Probable | CRITICAL | exposure | « Une machine à mauvaise réputation a une base de données exposée » |
| Réputation malveillante (VT) **+** SSH ouvert (Shodan) | Credential Stuffing Possible | HIGH | threat | « Mauvaise réputation plus SSH exposé » |

**Pourquoi c'est important :** chaque source est non concluante isolément. Un port RDP ouvert est courant ; une CVE critique existant dans NVD ne prouve pas que *cette* machine exécute le service vulnérable. Ce n'est qu'en *recoupant* les deux qu'un risque crédible émerge. Ce recoupement est le cœur intellectuel du projet.

---

## 9. Le modèle de scoring (`engine/scorer.py`)

### 9.1 Score de risque global (0–100)

- **Poids :** CRITICAL = 30, HIGH = 18, MEDIUM = 8, LOW = 3.
- **Bonus :** 2+ constats CRITICAL → +15 ; 1 CRITICAL + 2+ HIGH → +10.
- **Planchers :** le score ne peut jamais descendre sous la tranche de son pire constat (CRITICAL ≥ 75, HIGH ≥ 50, MEDIUM ≥ 25, LOW ≥ 5). Cela empêche un constat grave d'être affiché comme un risque LOW.
- **Plafond :** 100.
- **Tranches :** 0–24 LOW (vert), 25–49 MEDIUM (jaune), 50–74 HIGH (orange), 75–100 CRITICAL (rouge).
- Aucun constat → score 2,0 LOW.

Exemples :
- Cible propre → **2,0 LOW**.
- RDP + SSH exposés → **50 HIGH**.
- RDP + CVE critique → **93 CRITICAL**.
- Signalée par 30 moteurs antivirus → **75 CRITICAL**.

### 9.2 Profils Exposition / Menace (`calculate_profiles`)

Chaque constat appartient à une catégorie, le moteur calcule donc **deux indices indépendants** :

- **Indice d'exposition** — somme des poids des constats `exposure` (ports, CVE, intrusion/exfiltration), plancher selon le pire constat, plafonné à 100.
- **Indice de menace** — somme des poids des constats `threat` (réputation, credential stuffing), avec la même logique de plancher.

**Verdict** dérivé des deux indices :

| Tranche d'exposition | Tranche de menace | Verdict |
|---|---|---|
| HIGH/CRITICAL | HIGH/CRITICAL | Cible Exposée ET Acteur de Menace Potentiel |
| HIGH/CRITICAL | LOW/MEDIUM | Cible Potentielle : Asset Exposé / Compromettable |
| LOW/MEDIUM | HIGH/CRITICAL | Acteur de Menace Potentiel |
| MEDIUM | MEDIUM | Préoccupation Modérée |
| LOW | LOW | Faible Préoccupation — Ressource A Priori Saine |

Cela répond directement à la question : **« cette IP est-elle une victime (exposition) ou un danger pour les autres (menace), ou les deux ? »**

---

## 10. L'application web

### 10.1 Routes

| Route | Méthode | Page / action | Accès |
|---|---|---|---|
| `/` | GET | Tableau de bord : formulaire de scan + 5 scans récents | connecté |
| `/login`, `/register`, `/logout` | — | Authentification | public (logout : connecté) |
| `/scan` | POST | Lance l'analyse, enregistre le résultat | connecté |
| `/scan/<id>` | GET | Rapport d'intelligence complet | connecté |
| `/history` | GET | Tous les scans du compte | connecté |
| `/delete-scan/<id>` | POST | Supprimer un scan | propriétaire |
| `/settings` | GET/POST | Préférences visuelles (thème, interrupteurs) | connecté |
| `/settings/security` | POST | Changer le mot de passe | connecté |
| `/settings/intel` | POST | Enregistrer les clés d'accès par utilisateur | connecté |
| `/settings/alerts` | POST | Seuil d'alerte + URL webhook | connecté |
| `/control-panel` | GET | Gestion des utilisateurs | admin uniquement |
| `/delete-user/<id>` | POST | Supprimer un utilisateur | admin uniquement |

### 10.2 Authentification et rôles

- **Flask-Login** gère les sessions ; `@login_required` protège toutes les routes.
- **Flask-Bcrypt** hache les mots de passe (jamais stockés en clair).
- Deux rôles : `user` et `admin`. Le panneau de contrôle et la suppression d'utilisateurs sont **réservés à l'admin** — un bug d'élévation de privilèges où n'importe quel utilisateur pouvait supprimer les autres a été corrigé.
- Administrateur par défaut : `admin` / `adminpassword123` (créé automatiquement au démarrage).

### 10.3 Page de rapport (`target_details.html`)

Le rapport est organisé ainsi :
1. **En-tête** — cible, badge IP/Domaine, score de risque global avec couleur.
2. **Profil de cible (Exposition vs Menace)** — verdict, deux indices avec barres colorées.
3. **Origine & Réseau** — géolocalisation.
4. **Infrastructure & Ports** — organisation, noms d'hôtes, OS, ports ouverts, vulnérabilités connues (CVE avec scores CVSS).
5. **Télémétrie de menace** — compteurs de moteurs VirusTotal.
6. **Constat du moteur de corrélation** — chaque constat avec badge de sévérité, badge de catégorie EXPOSURE/THREAT, description et recommandation.
7. **Domaine & Registraire / TLS** — enregistrement RDAP et détails du certificat. Ces sections sont **masquées pour les cibles IP**, remplacées par une courte explication, car les enregistrements de domaine et les certificats TLS ne concernent que les noms de domaine.

### 10.4 Décisions UX

- Les noms de fournisseurs/services (Shodan, VirusTotal, NVD, SQLite, etc.) **ne sont pas exposés dans l'interface** ; l'interface présente le propre modèle d'information du produit (Organization, Known Vulnerabilities, Threat Telemetry, etc.).
- Les rapports s'adaptent au type de cible : badge IP vs Domaine, et widgets spécifiques aux domaines masqués pour les IP avec explication.

---

## 11. Modèle de données (`models.py`)

**User**
`id`, `username` (unique), `password` (haché bcrypt), `role`, `virustotal_key`, `abuseipdb_key`, `shodan_key`, `theme`, `alert_threshold`, `webhook_url`, `enable_particles`, `enable_crt`.

**ScanResult**
`id`, `user_id` (clé étrangère), `target`, `scan_date`, `geolocation_data`, `shodan_data`, `vt_data`, `whois_data`, `ssl_data`, `findings_data` (tous stockés en **JSON textuel**), `risk_score`, `risk_level`, `risk_color`, `exposure_index`, `threat_index`, `exposure_band`, `threat_band`, `profile`.

**Note de conception :** les réponses d'API ont des formes irrégulières ; les stocker en JSON textuel garde le schéma flexible, et le score/les constats analysés sont rendus à l'affichage. Une routine légère de migration au démarrage (`ALTER TABLE ... ADD COLUMN`) met à niveau les bases existantes lorsque de nouveaux champs sont ajoutés.

---

## 12. Correctifs et décisions d'ingénierie (important)

Ce sont les corrections apportées pendant le développement, chacune avec sa justification technique :

1. **Parsing réel des CVSS depuis Shodan** — auparavant, chaque CVE de Shodan recevait un 7.5/HIGH codé en dur. Le vrai score CVSS retourné par Shodan est maintenant parsé et converti en sévérité.
2. **Résolution des scores InternetDB** — InternetDB gratuit renvoie des ID CVE sans score ; le moteur résout chaque ID exact auprès de NVD pour que chaque vulnérabilité ait un vrai score. Aucune sévérité fabriquée.
3. **Tranches de sévérité VirusTotal** — auparavant chaque moteur malveillant créait un constat CRITICAL, si bien que 4 moteurs plafonnaient le score à 100 instantanément. Des tranches sont maintenant utilisées (≥6 moteurs = CRITICAL, 1–5 = MEDIUM).
4. **Suppression du bruit par mots-clés NVD** — la recherche par mots-clés générique renvoyait des CVE hors sujet et gonflait les scores. Le flux par défaut n'utilise que les recherches par ID exact.
5. **Planchers de scoring** — un seul constat HIGH pouvait auparavant donner un score LOW. Les planchers garantissent que le score reflète son pire constat.
6. **Hachage bcrypt des mots de passe** — les mots de passe étaient stockés en clair ; ils sont maintenant hachés avec Flask-Bcrypt (avec un repli sûr pour les lignes héritées).
7. **Secrets dans `.env`** — les clés API étaient codées en dur dans `config.py` ; elles sont maintenant chargées depuis `.env` (gitignoré), avec `.env.example` comme modèle.
8. **Restriction admin** — le panneau de contrôle et la suppression d'utilisateurs étaient accessibles à tous ; désormais réservés à `role == 'admin'`.
9. **Routes de paramètres manquantes** — les formulaires de paramètres renvoyaient 405 ; les routes POST manquantes ont été implémentées.
10. **Vrai RDAP / WHOIS** — le module WHOIS était un placeholder renvoyant des chaînes codées en dur (« Verified Registrar / Enrolled Domain ») ; il a été remplacé par de vraies recherches RDAP renvoyant registraire et dates réels.
11. **Parsing du certificat TLS** — la détection SSL était silencieusement cassée pour *toutes* les cibles : avec la vérification `CERT_NONE`, `getpeercert()` de Python renvoie un dictionnaire vide, si bien que `has_ssl` était toujours faux. Corrigé en lisant les octets DER bruts et en les décodant avec la bibliothèque `cryptography` (les certificats valides, expirés ou auto-signés se parsent tous correctement).
12. **Dégradation gracieuse** — chaque appel externe est protégé contre les exceptions avec des timeouts courts ; les clés manquantes produisent des zéros/N/A, jamais de crash ni de données fabriquées.
13. **Colonnes de profil persistées** — les indices d'exposition/menace et le verdict sont stockés par scan et affichés dans l'historique.

---

## 13. Tests

Tests unitaires dans `test/test_correclator.py` (`unittest` de Python) :

1. Un port RDP ouvert génère un constat d'exposition HIGH.
2. Plus de 20 ports déclenchent un constat CRITICAL et un bonus de score.
3. Une cible propre reçoit un niveau de risque LOW.
4. Les ports ouverts poussent l'axe **Exposition**, pas l'axe Menace.
5. Une réputation malveillante pousse l'axe **Menace**, pas l'axe Exposition.
6. Chaque constat porte une catégorie exposition/menace valide.

Exécution :
```
python -m unittest test.test_correclator -v
```

Tous les tests passent. Une vérification de bout en bout complète (connexion → scan en direct → page de rapport → ligne en base) a également été réalisée via le client de test Flask.

---

## 14. Exécution du projet

```
python main.py
```
Puis ouvrir `http://localhost:5000`. Connexion : `admin` / `adminpassword123`.

Installation des dépendances :
```
python -m pip install -r requirements.txt
```

Notes d'environnement importantes :
- Exigence : **Python 3.13** avec les dépendances de `requirements.txt` installées.
- Un accès Internet est nécessaire pour les scans en direct ; l'application elle-même fonctionne hors ligne.

---

## 15. Clés API et limites d'usage

| Service | Offre gratuite | Notes |
|---|---|---|
| ip-api | Gratuit, sans clé | — |
| API officielle Shodan | 100 crédits **au total** (une fois) | Le repli InternetDB est gratuit et illimité |
| NVD | Gratuit, sans clé | Recherches par ID exact |
| VirusTotal | ~500 requêtes/jour, 4/minute | Optionnelle |
| RDAP | Gratuit, sans clé | Les registres limitent le débit ; éviter les scans massifs |

Les clés par utilisateur se configurent dans Paramètres → Intelligence ; elles priment sur les clés globales du `.env`.

---

## 16. Limites connues

1. **Rapport PDF non encore implémenté** — ReportLab est installé ; le modèle de données stocke déjà tout le nécessaire, mais il n'y a encore ni sortie `reports/` ni bouton de téléchargement.
2. **Vérification de courriels compromis non implémentée** — le cahier des charges mentionne les vérifications de courriels compromis (HIBP) ; l'API payante HIBP est le blocage. Une alternative gratuite (par exemple XposedOrNot) est prévue.
3. **La détection CVE de Shodan repose sur l'empreinte logicielle** — elle signale des vulnérabilités *potentielles*, pas la preuve d'exploitation (les constats sont volontairement nommés « potentielle »).
4. **Pas de protection CSRF** sur les formulaires ni de **limitation de débit de connexion** — points de durcissement.
5. **Pas de graphiques** (le cahier des charges mentionne Chart.js) — les données sont stockées ; la visualisation est une étape de finition.
6. **Les alertes webhook sont enregistrées mais pas encore envoyées**.
7. **Pas de déduplication des scans** — re-scanner la même cible crée une nouvelle ligne (une couche de cache est prévue pour protéger les quotas API).

---

## 17. Feuille de route (travaux prévus)

Voici les améliorations que je souhaite ajouter ensuite — un simple aperçu de la direction du projet :

1. **Extraction du rapport PDF** — un téléchargement en un clic d'un rapport professionnel pour tout scan (ReportLab est déjà installé ; les données nécessaires sont déjà stockées).
2. **Mini-carte de géolocalisation interactive** — une petite carte sur le tableau de bord montrant la localisation physique de la cible scannée.
3. **Renseignements sur les courriels compromis (HIBP)** — vérifier si des adresses courriel apparaissent dans des fuites de données connues (une API gratuite est prévue, l'API payante HIBP étant le blocage actuel).
4. **Tableaux de bord Chart.js** — tendances visuelles du risque à travers l'historique des scans.
5. **Durcissement de la sécurité** — protection CSRF sur tous les formulaires et limitation de débit de connexion.
6. **Livraison des alertes** — envoyer réellement les alertes webhook/courriel lorsqu'un scan dépasse le seuil configuré.
7. **Couche de cache** — éviter de re-interroger les API pour des cibles récemment scannées afin de protéger les quotas API.

---

## 18. État d'avancement honnête pour l'encadrant

**Complet et fonctionnel aujourd'hui :**
- Pipeline de scan complet sur 5 sources avec replis gracieux.
- Moteur de corrélation maison (ports, CVE, réputation, 3 règles de corrélation croisée).
- Modèle de scoring transparent avec planchers.
- Profilage Exposition vs Menace avec verdict par cible.
- Application web : authentification, rôles, paramètres, historique, page de rapport, panneau admin.
- Données d'enregistrement RDAP réelles et parsing réel des certificats TLS.
- Persistance en base et migrations automatiques.
- 6 tests unitaires passants + vérification de bout en bout.

**Pas encore fait (prévu ensuite) :**
- Extraction du rapport PDF.
- Mini-carte de géolocalisation interactive sur le tableau de bord.
- Vérifications de courriels compromis (HIBP).
- Tableaux de bord Chart.js.
- Protection CSRF et limitation de débit de connexion.
- Livraison des alertes et couche de cache.

---

*Fin du rapport.*
