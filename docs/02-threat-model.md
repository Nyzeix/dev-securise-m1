# Threat Model STRIDE - TaskFlow

## Composant 1: Authentification (/auth/register, /auth/login)

| STRIDE | Menace identifiee | Probabilite | Impact | Priorite |
|---|---|---|---|---|
| S | Usurpation via vol/rejeu de token | Moyenne | Critique | P0 |
| T | Alteration du payload JWT si secret compromis | Moyenne | Critique | P0 |
| R | Traces insuffisantes des tentatives de connexion | Moyenne | Moyenne | P2 |
| I | Divulgation d'informations via messages d'erreur | Moyenne | Haute | P1 |
| D | Brute force sur endpoint login | Haute | Haute | P1 |
| E | Elevation de privilege via token admin forge | Moyenne | Critique | P0 |

## Composant 2: Gestion des taches (/tasks)

| STRIDE | Menace identifiee | Probabilite | Impact | Priorite |
|---|---|---|---|---|
| S | Usurpation d'identite via token non valide | Moyenne | Haute | P1 |
| T | Modification de taches d'un tiers (IDOR) | Moyenne | Haute | P1 |
| R | Absence d'audit sur suppression/modification | Moyenne | Moyenne | P2 |
| I | Lecture non autorisee de donnees privees | Moyenne | Haute | P1 |
| D | Spam de creation de taches | Faible | Moyenne | P3 |
| E | Acces a des donnees admin via contournement ACL | Faible | Haute | P2 |

## Composant 3: Administration (/admin/users)

| STRIDE | Menace identifiee | Probabilite | Impact | Priorite |
|---|---|---|---|---|
| S | Acces admin par compte non admin | Moyenne | Critique | P0 |
| T | Alteration de roles utilisateurs | Faible | Critique | P1 |
| R | Journalisation insuffisante des actions admin | Moyenne | Haute | P2 |
| I | Exposition des donnees utilisateurs | Moyenne | Critique | P0 |
| D | Suppression en masse d'utilisateurs | Faible | Haute | P2 |
| E | Elevation des privileges par erreur de controle role | Moyenne | Critique | P0 |

## Synthese priorisation

- Menaces P0: 5
- Menaces P1: 6
- Menaces P2/P3: 7

Les risques P0/P1 seront traites en priorite dans les modules M2 a M5.
