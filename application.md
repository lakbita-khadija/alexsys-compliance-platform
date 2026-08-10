# Application

## 1. Overview — PARTIALLY IMPLEMENTED

Aucun dossier `application/` n'existe. Le rôle applicatif (orchestration
d'un use case, appel du domaine sans logique métier propre) est rempli
**informellement** par `ScanService` (`scan_service.py`, 190 lignes).

## 2. Use Cases (CURRENT CODE — un seul, informel)

| Use case de fait | Méthode | Entrée | Sortie |
|---|---|---|---|
| Exécuter un scan complet | `ScanService.run(tenant_id, previous_resources=None, previous_scan_id=None)` | `tenant_id`, snapshot précédent optionnel | `ScanReport` |

`ScanService.run` orchestre, dans cet ordre exact (vérifié dans le code) :
collecte → construction du graphe → évaluation des règles → analyse Attack
Path → enrichissement du risque → Drift (si snapshot fourni). Aucune ligne
de `boto3`/SQL n'y apparaît directement — les collecteurs et futurs
repositories restent des dépendances injectées.

## 3. DTOs / Commands / Queries — NOT IMPLEMENTED

Aucun DTO distinct de l'entité de domaine n'existe encore ; `ScanReport`
(dataclass, `scan_service.py`) sert à la fois de résultat interne et de
sortie — pas encore de séparation Commande/Requête/DTO formelle.

## 4. Ports — NOT IMPLEMENTED

`BaseCollector` (`collectors/base.py`) joue de fait le rôle d'un port
(interface abstraite implémentée par `MockAwsCollector` et `AwsCollector`),
mais n'est pas situé dans un dossier `application/ports/` dédié.

## 5. Common Mistakes

**Architecturale** : le risque principal ici est qu'à mesure que de
nouveaux use cases apparaîtront (persistance, API), la couche applicative
reste "informelle" trop longtemps, diluant la frontière entre orchestration
et détail technique. Voir `13-decisions/architecture-decisions.md`.
