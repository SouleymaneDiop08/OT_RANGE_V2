# Talixman Cyber Range Portal

Interface web sécurisée d'accès aux conteneurs ICSHUB.

## Fonctionnalités
- **Authentification** JWT avec cookie httpOnly + rate limiting (10 tentatives / 15 min)
- **Compte admin par défaut** : `admin` / `admin` (à changer impérativement)
- **Portal** : cards cliquables vers chaque interface de conteneur
- **Gestion utilisateurs** (admin) : création, modification, suppression
- **Modification de profil** pour tous les utilisateurs

## Services exposés dans le portail
| Service | Port hôte |
|---|---|
| SCADA Central | 1884 |
| SCADA Station A | 1881 |
| SCADA Station B | 1882 |
| PLC Station A | 8080 |
| PLC Station B | 8081 |
| Engineering WS (noVNC) | 6080 |
| Kali Attacker (noVNC) | 6081 |
| Routeur R1-R3 | 1444 |
| Routeur R2-R3 | 1443 |

## Installation

```bash
# Copiez le dossier portal/ dans votre répertoire ICSHUB
# Ajoutez le service dans docker-compose.yml (voir INTEGRATION.yml)

docker compose up --build portal
```

## Accès
```
http://localhost
Username : admin
Password : admin
```

## Sécurité
- Changez `JWT_SECRET` dans le docker-compose en production
- Changez le mot de passe admin dès la première connexion
- Le portal est sur le réseau L3 (192.168.30.5)
