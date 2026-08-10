# Architectural Gaps — consolidés, classés par gravité

Trouvés en documentant (pas supposés à l'avance) et référencés à leur
fichier source pour vérification.

## CRITICAL

Aucun gap classé CRITICAL — aucune faille de sécurité active exploitable
sur le périmètre actuel (pas d'API exposée, pas de credential stocké).

## HIGH

| # | Problème | Preuve | Impact | Recommandation | Composant | Phase |
|---|---|---|---|---|---|---|
| 1 | Aucune Anti-Corruption Layer avec rédaction des secrets | `10-security/threat-model.md` | Une configuration cloud collectée pourrait un jour contenir un secret exposé sans filtrage | Implémenter l'ACL avant toute exposition externe des `Finding` | Frontière AI Service | Phase 11 (blueprint antérieur) |
| 2 | Aucune pagination dans les appels AWS (`list_buckets`, `describe_security_groups`, `list_users`) | `03-scanner/discovery.md` | Sur un compte avec beaucoup de ressources, une collecte silencieusement incomplète | Ajouter la gestion de `NextToken`/`Marker` | `collectors/aws_collector.py` | Avant Phase 9 (validation AWS) |
| 3 | Drift Detection sans baseline persistée | `05-security-analysis/drift-detection.md` | Ne fonctionne qu'avec un couple de snapshots fourni manuellement, pas entre deux vrais scans historiques | Persistance des scans (Phase 5 du blueprint antérieur) | `drift/` | Phase 5 |

## MEDIUM

| # | Problème | Preuve | Impact |
|---|---|---|---|
| 4 | Sur-attribution des `contributing_finding_ids` sur un Attack Path | `05-security-analysis/attack-paths.md` | Un finding sans lien causal réel apparaît comme contributeur d'un chemin |
| 5 | `resource_type` n'est pas un type canonique provider-agnostique | `03-scanner/normalization.md` | Une future ressource Azure équivalente à un S3 bucket ne déclencherait pas automatiquement les mêmes règles |
| 6 | Pas de modèle formel de Resource Inventory (8 états CSPM) | `03-scanner/resource-inventory.md` | Un futur widget "taux de couverture" serait mal fondé sans cette distinction |

## LOW

| # | Problème | Preuve |
|---|---|---|
| 7 | 6 opérateurs supportés par le moteur ne sont utilisés par aucune des 33 règles réelles | `04-compliance/yaml-rules.md` |
| 8 | AND/OR/NOT et fonctions contextuelles implémentées mais utilisées par aucune règle réelle | `04-compliance/yaml-rules.md` |
| 9 | Pas de suite `tests/rules/` par `rule_id` individuel | `09-testing/rule-coverage.md` |
| 10 | Absence d'eval()/exec() vérifiée seulement par grep statique, pas par un test CI dédié | `04-compliance/policy-engine.md` |

## Ordre de résolution recommandé

1. Gaps HIGH #1 et #2 (sécurité et fiabilité de la collecte) — avant toute
   démonstration contre un vrai compte AWS
2. Gap HIGH #3 (persistance) — prérequis de plusieurs autres phases
3. Gaps MEDIUM — au fil des phases concernées, non bloquants
4. Gaps LOW — opportunistes, jamais prioritaires sur une phase fonctionnelle
