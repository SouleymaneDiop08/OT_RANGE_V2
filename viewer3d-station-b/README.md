# Station B - 3D Real-Time Viewer

Visualisation 3D temps reel de la station electrique B (poste de transformation).
**Mode READ-ONLY uniquement** - aucune capacite d'ecriture vers le PLC.

## Objectif

Outil de demonstration et sensibilisation client pour illustrer:
- La telemetrie temps reel d'un poste electrique
- L'etat des disjoncteurs et sectionneurs
- Les metriques de temperature des transformateurs
- Les courants et desequilibres des departs (feeders)
- La visualisation des alarmes

## Architecture

```
+-------------------+     Modbus TCP (R/O)     +----------------+
|  3D Viewer        | -----------------------> |  PLC Station B |
|  (Python/aiohttp) |      Port 502            |  (OpenPLC)     |
+-------------------+                          +----------------+
         |
         | WebSocket
         v
+-------------------+
|  Frontend 3D      |
|  (Three.js)       |
+-------------------+
```

## Demarrage

### Option 1: Avec Docker Compose (recommande)

```bash
# Depuis le repertoire ICSHUB
cd /home/kakashi_/ICSHUB

# Demarrer tous les services (incluant le viewer)
docker compose up -d

# Ou demarrer uniquement le viewer (si le PLC est deja en cours)
docker compose up -d viewer3d_station_b

# Verifier le statut
docker compose ps viewer3d_station_b

# Voir les logs
docker compose logs -f viewer3d_station_b
```

### Option 2: Developpement local (sans Docker)

```bash
cd /home/kakashi_/ICSHUB/viewer3d-station-b

# Installer les dependances
pip install -r backend/requirements.txt

# Lancer le serveur (mode simulation si PLC non accessible)
python backend/telemetry_server.py --host 0.0.0.0 --port 8090 --static frontend/static
```

## Acces

| Service | URL | Description |
|---------|-----|-------------|
| Vue 3D | http://localhost:8090 | Interface principale |
| API Status | http://localhost:8090/api/status | Etat du serveur |
| API Telemetry | http://localhost:8090/api/telemetry | Donnees JSON |
| WebSocket | ws://localhost:8090/ws | Flux temps reel |

## Integration FUXA (iframe)

Pour integrer la vue 3D dans FUXA Station B:

1. Ouvrir FUXA sur http://localhost:1882
2. Ajouter un composant "Html/Iframe"
3. Configurer l'URL: `http://localhost:8090`
4. Ajuster la taille selon les besoins

**Note**: Pour l'integration iframe depuis un autre conteneur, utiliser l'IP interne:
`http://192.168.20.90:8090`

## Mapping Modbus (Read-Only)

Le viewer lit les registres suivants du PLC Station B (192.168.20.10:502):

### Coils (%QX) - Function 01
| Adresse | Variable | Description |
|---------|----------|-------------|
| 0 | CMD_CB_Toggle | Disjoncteur principal |
| 1 | CMD_DS_Line_Toggle | Sectionneur ligne |
| 2 | CMD_DS_Bus_Toggle | Sectionneur barre |
| 3 | CMD_TX1_CB_Toggle | Disjoncteur Transfo 1 |
| 4 | CMD_TX1_DS_Bus_Toggle | Sectionneur Bus Transfo 1 |
| 5 | CMD_TX2_CB_Toggle | Disjoncteur Transfo 2 |
| 6 | CMD_TX2_DS_Bus_Toggle | Sectionneur Bus Transfo 2 |
| 8 | CMD_Feeder1_CB | Disjoncteur Depart 1 |
| 9 | CMD_Feeder2_CB | Disjoncteur Depart 2 |

### Input Registers (%IW) - Function 04
| Adresse | Variable | Unite | Description |
|---------|----------|-------|-------------|
| 0 | MET_Freq | Hz | Frequence reseau |
| 1 | MET_Bus_Voltage | kV | Tension barre omnibus |
| 2 | MET_L1_Voltage | kV | Tension ligne 1 |
| 3 | MET_L1_Current | A | Courant ligne 1 |
| 4 | MET_L1_Power | MW | Puissance ligne 1 |
| 8-9 | MET_TX1_OilTemp/WindingTemp | C | Temperatures Transfo 1 |
| 10-11 | MET_TX2_OilTemp/WindingTemp | C | Temperatures Transfo 2 |
| 12-13 | MET_TX1/TX2_Output_Voltage | kV | Tensions sortie transfos |
| 20-25 | Feeder 1 currents | A/% | Courants et desequilibre |
| 30-35 | Feeder 2 currents | A/% | Courants et desequilibre |

### Discrete Inputs (%IX) - Function 02
| Adresse | Variable | Description |
|---------|----------|-------------|
| 0 | STS_Busbar_Live | Barre sous tension |
| 16-18 | ALM_Fdr1_* | Alarmes Depart 1 |
| 19-21 | ALM_Fdr2_* | Alarmes Depart 2 |
| 24-25 | ALM_TX1_Temp_* | Alarmes temperature TX1 |
| 26-27 | ALM_TX2_Temp_* | Alarmes temperature TX2 |

### Holding Registers (%MW) - Function 03
| Adresse | Variable | Unite | Description |
|---------|----------|-------|-------------|
| 0 | SET_TX1_Voltage | kV | Consigne tension TX1 |
| 1 | SET_TX2_Voltage | kV | Consigne tension TX2 |

## Mode Simulation

Si le PLC n'est pas accessible, le viewer passe automatiquement en mode simulation:
- Donnees realistes generees localement
- Indicateur "MODE SIMULATION" affiche
- Utile pour les demonstrations hors environnement complet

## Securite

- **READ-ONLY**: Aucune fonction d'ecriture Modbus n'est implementee
- **Pas de credentials**: Pas de stockage de mots de passe
- **Container non-root**: Le serveur tourne sous un utilisateur non-privilegie
- **Pas d'acces shell**: Aucune route d'execution de commandes

## Fichiers

```
viewer3d-station-b/
├── Dockerfile              # Image Docker
├── README.md               # Cette documentation
├── backend/
│   ├── modbus_mapping.py   # Mapping Modbus Station B
│   ├── requirements.txt    # Dependances Python
│   └── telemetry_server.py # Serveur telemetrie
└── frontend/
    └── static/
        └── index.html      # Interface 3D (Three.js)
```

## Limitations MVP

- Visualisation 3D simplifiee (schema unifilaire basique)
- Pas de persistance des donnees historiques
- Pas d'authentification utilisateur
- Pas d'export de donnees

## Troubleshooting

**Le viewer affiche "MODE SIMULATION":**
- Verifier que plc_station_b est demarre: `docker compose ps plc_station_b`
- Verifier la connectivite reseau: `docker exec icshub_viewer3d_station_b ping 192.168.20.10`

**WebSocket se deconnecte:**
- Verifier les logs: `docker compose logs viewer3d_station_b`
- Le viewer se reconnecte automatiquement apres 2 secondes

**Page blanche:**
- Verifier que Three.js CDN est accessible
- Ouvrir la console navigateur (F12) pour voir les erreurs
