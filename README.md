# Tenable.io API Simulator

Simulateur de l'API Tenable.io (Tenable Vulnerability Management) pour tester et démontrer l'intégration Cortex XSIAM **Tenable.io** (pack `Tenable_io`) sans avoir accès à un tenant Tenable réel.

Basé sur [xsiam-simulator-template](https://github.com/JCourtemanche/xsiam-simulator-template) et le package partagé [xsiam-shared-personas](https://github.com/JCourtemanche/xsiam-shared-personas) — les mêmes utilisateurs, hostnames et IPs Business Corp apparaissent à travers tous les simulateurs.

## Contrat API reproduit

- **Auth** : header `X-ApiKeys: accessKey=<access>; secretKey=<secret>`
- **Format** : **JSON** partout
- **Base URL** : `https://cloud.tenable.com/` (identique)
- **Flow critique** : exports asynchrones en 3 étapes (POST create → GET status en boucle jusqu'à `FINISHED` → GET chunks)

## Endpoints couverts

### Scans

| Méthode | Endpoint | Commande XSIAM |
|---|---|---|
| GET | `/scans` | `tenable-io-list-scans` (aussi `test-module`) |
| GET | `/scans/<id>` | `tenable-io-get-scan-report` |
| GET | `/scans/<id>/history` | `tenable-io-get-scan-history` |
| POST | `/scans/<id>/launch` | `tenable-io-launch-scan` |
| POST | `/scans/<id>/pause` | `tenable-io-pause-scan` |
| POST | `/scans/<id>/resume` | `tenable-io-resume-scan` |
| POST | `/scans/<id>/export` | `tenable-io-export-scan` (init) |
| GET | `/scans/<id>/export/<file>/status` | (poll) |
| GET | `/scans/<id>/export/<file>/download` | (download PDF/CSV) |
| GET | `/filters/scans/reports` | `tenable-io-list-scan-filters` |

### Workbenches

| Méthode | Endpoint | Commande XSIAM |
|---|---|---|
| GET | `/workbenches/assets/<uuid>/info` | `tenable-io-get-asset-details` |
| GET | `/workbenches/assets/<uuid>/vulnerabilities` | `tenable-io-get-vulnerabilities-by-asset` |
| GET | `/workbenches/vulnerabilities/<plugin_id>/info` | `tenable-io-get-vulnerability-details` |
| GET | `/api/v3/assets/<uuid>/attributes` | (asset attributes) |

### Exports asynchrones (fetch-assets flow)

| Méthode | Endpoint |
|---|---|
| POST | `/assets/export` → `{export_uuid}` |
| GET | `/assets/export/<uuid>/status` → `{status: QUEUED/PROCESSING/FINISHED, chunks_available: []}` |
| GET | `/assets/export/<uuid>/chunks/<id>` → array d'assets |
| POST | `/vulns/export` → `{export_uuid}` |
| GET | `/vulns/export/<uuid>/status` |
| GET | `/vulns/export/<uuid>/chunks/<id>` → array de vulnérabilités |

Le state machine :
- `QUEUED` au 1er GET status
- `PROCESSING` au 2ème
- `FINISHED` avec `chunks_available: [1]` au 3ème (configurable via `EXPORT_POLLS_TO_FINISH`)

### Audit log

| Méthode | Endpoint | Commande XSIAM |
|---|---|---|
| GET | `/audit-log/v1/events` (filtres `f=date.gt:...`, `f=date.lt:...`, `limit=...`) | `tenable-io-get-audit-logs` (fetch-events) |

## Dataset

- **40 plugins** Tenable avec plugin_id (200000+), CVE réels, family (Windows, Firewalls, CGI abuses, Web Servers, MacOS X Local Security Checks...), severity 0..4, CVSS v3 base + temporal + vector, VPR score, exploit_available, has_patch, patch_publication_date, solution
- **18 assets** : 6 personas Business Corp + 12 serveurs générés — chacun avec UUID, ipv4, mac, netbios, operating_systems, sources (NESSUS_AGENT/NESSUS_SCAN), tags, acr_score, exposure_score
- **~255 findings** (asset × vuln pairs) au format `/vulns/export` (avec `asset`, `plugin`, `port`, `scan`, `severity`, `first_found`, `last_found`, `state=OPEN`)
- **8 scans historiques** (dont 1 running, 1 canceled) avec pause/resume/launch stateful
- **6 templates de scan** (Advanced, Basic Network, Discovery, Agent, PCI, Web)
- **4 filter definitions** utilisées par la UI de scan
- **200 audit log events** (login, scan launched/finished, policy create/edit, tag create/edit...)

## Datasets XSIAM cibles

Le pack Tenable.io envoie via `send_data_to_xsiam(vendor="tenable", product=<X>)`. Deux datasets sont alimentés :

| Dataset XSIAM | Source | Alimenté par |
|---|---|---|
| `tenable_io_raw` | Audit logs + assets export | `send_data_to_xsiam(events, vendor="tenable", product="io")` (fetch-events + fetch-assets pour la partie assets) |
| `tenable_io_vulnerabilities_raw` | Vulns export | `send_data_to_xsiam(vulnerabilities, vendor="tenable", product="io_vulnerabilities")` (fetch-assets, stage vulns) |

Une fois le fetch effectué, tu peux requêter en XQL :

```
dataset = tenable_io_vulnerabilities_raw
| filter severity = "critical"
| fields plugin.cve, plugin.name, asset.hostname, asset.ipv4, plugin.cvss3_base_score
| limit 100
```

Comme pour Cyberwatch, Rapid7 et Qualys, **le pack ne ship pas de Modeling Rules** — la donnée arrive brute dans les datasets `_raw` et n'apparaît pas nativement dans Cortex Exposure Management. Si tu veux la voir dans Exposure Management, tu peux réutiliser le pattern **BYOS importer** qu'on a fait pour Cyberwatch (adaptable en remplaçant la commande source Cyberwatch par `tenable-io-get-vulnerabilities-by-asset` ou par l'export asynchrone).

## Installation locale

```bash
cd simulator
pip install -r requirements.txt
python app.py
# -> http://localhost:8080
```

### Tests rapides

```bash
# Health (sans auth)
curl http://localhost:8080/health

# Liste scans
curl -H "X-ApiKeys: accessKey=tenable-access-key; secretKey=tenable-secret-key" \
  http://localhost:8080/scans

# Détail asset
curl -H "X-ApiKeys: accessKey=tenable-access-key; secretKey=tenable-secret-key" \
  http://localhost:8080/workbenches/assets/<uuid>/info

# Détail vulnérabilité par plugin
curl -H "X-ApiKeys: accessKey=tenable-access-key; secretKey=tenable-secret-key" \
  http://localhost:8080/workbenches/vulnerabilities/200000/info

# Flow d'export assets (async)
curl -X POST -H "X-ApiKeys: accessKey=tenable-access-key; secretKey=tenable-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"chunk_size": 500, "filters": {}}' \
  http://localhost:8080/assets/export
# -> {"export_uuid": "..."}

curl -H "X-ApiKeys: accessKey=tenable-access-key; secretKey=tenable-secret-key" \
  http://localhost:8080/assets/export/<uuid>/status
# Poll jusqu'à {"status":"FINISHED","chunks_available":[1]}

curl -H "X-ApiKeys: accessKey=tenable-access-key; secretKey=tenable-secret-key" \
  http://localhost:8080/assets/export/<uuid>/chunks/1

# Audit log events (fetch-events)
curl -H "X-ApiKeys: accessKey=tenable-access-key; secretKey=tenable-secret-key" \
  "http://localhost:8080/audit-log/v1/events?limit=10"
```

## Déploiement sur GCP Cloud Run

```bash
bash deploy-cloudrun.sh
# ou avec creds custom
TENABLE_ACCESS_KEY=myaccess TENABLE_SECRET_KEY=mysecret bash deploy-cloudrun.sh
```

## Configuration dans XSIAM

**Settings → Integrations → Tenable Vulnerability Management** :

| Paramètre | Valeur |
|---|---|
| Server URL | `https://tenable-simulator-<hash>-ew.a.run.app/` |
| Access Key | `tenable-access-key` |
| Secret Key | `tenable-secret-key` |
| Trust any certificate | *(non nécessaire, Cloud Run cert valide)* |

## Structure du projet

```
tenable-simul/
├── README.md
├── cloudbuild.yaml
├── deploy-cloudrun.sh
├── deployment/
│   ├── Dockerfile
│   └── app.yaml
└── simulator/
    ├── app.py                # Flask app factory + blueprint registration
    ├── auth.py               # X-ApiKeys header parsing + validation
    ├── config.py             # env vars: keys, dataset sizes, EXPORT_POLLS_TO_FINISH
    ├── requirements.txt
    ├── generators/
    │   ├── base.py           # personas + OS + severity + iso_z / epoch_s helpers
    │   ├── vulnerabilities.py# 40 plugins with CVE / CVSS v2/v3 / VPR / solution
    │   ├── assets.py         # 18 assets + payload builders (workbench + exports)
    │   ├── scans.py          # 8 scans + filters + ScanStore live state
    │   ├── exports.py        # ExportStore state machine (QUEUED->PROCESSING->FINISHED)
    │   ├── audit_logs.py     # 200 audit events
    │   └── catalog.py        # instantiation unique
    └── routes/
        ├── _helpers.py       # not_found()
        ├── scans.py          # /scans, /scans/<id>[/history|/launch|/pause|/resume|/export/...], /filters/scans/reports
        ├── workbenches.py    # /workbenches/assets/<uuid>[/info|/vulnerabilities], /workbenches/vulnerabilities/<pid>/info, /api/v3/assets/<uuid>/attributes
        ├── exports_assets.py # /assets/export + /status + /chunks
        ├── exports_vulns.py  # /vulns/export + /status + /chunks
        └── audit_log.py      # /audit-log/v1/events
```

## Personas partagés — Business Corp

Ces données viennent de [xsiam-shared-personas](https://github.com/JCourtemanche/xsiam-shared-personas) et sont identiques dans tous les simulateurs.

| Utilisateur | Email | Hostname | IP | OS |
|---|---|---|---|---|
| Alice Dupont | alice.dupont@business.org | BSNS-WIN-ALICE | 192.168.1.1 | Windows 10 Pro |
| Bob Martin | bob.martin@business.org | BSNS-MAC-BOB | 192.168.1.2 | macOS 13 Ventura |
| Charlie Durant | charlie.durant@business.org | BSNS-WIN-CHARLIE | 192.168.1.3 | Windows 11 Pro |
| David Lefebvre | david.lefebvre@business.org | BSNS-WIN-DAVID | 192.168.1.4 | Windows 10 Pro |
| Emma Leroy | emma.leroy@business.org | BSNS-MAC-EMMA | 192.168.1.5 | macOS 14 Sonoma |
| Flora Moreau | flora.moreau@business.org | BSNS-MOB-FLORA | 192.168.1.6 | iOS 17 |

## Simulateurs frères

| Projet | API simulée |
|---|---|
| [proofpoint-tap-simulator](https://github.com/JCourtemanche/proofpoint-tap-simulator) | ProofPoint TAP |
| [sentinelone-simul](https://github.com/JCourtemanche/sentinelone-simul) | SentinelOne |
| [cato-networks-simul](https://github.com/JCourtemanche/cato-networks-simul) | Cato Networks |
| [cyberwatch-simul](https://github.com/JCourtemanche/cyberwatch-simul) | Cyberwatch |
| [Rapid7InsightVM-simul](https://github.com/JCourtemanche/Rapid7InsightVM-simul) | Rapid7 Nexpose / InsightVM (on-prem) |
| [qualys-simul](https://github.com/JCourtemanche/qualys-simul) | Qualys VMDR |
| [tenable-simul](https://github.com/JCourtemanche/tenable-simul) | Tenable.io (Tenable Vulnerability Management) |
