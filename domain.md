# Domain

## 1. Overview

Le domaine contient toute la logique métier : entités, value objects,
services de domaine. Vérifié : aucune dépendance à `boto3`, `azure-sdk`,
`fastapi`, `sqlalchemy` dans les fichiers listés ci-dessous
(`grep -rn "^import\|^from" scanner/schema.py scanner/value_objects.py
scanner/conditions.py scanner/rule_engine.py scanner/graph/ scanner/attack_path/
scanner/drift/` → seule dépendance externe : `pydantic`, `yaml` pour le
chargement — `yaml` reste défendable comme appartenant au domaine puisqu'il
ne fait qu'interpréter une syntaxe déclarative, sans SDK cloud impliqué).

## 2. Entities (CURRENT CODE)

| Entité | Fichier | Identité |
|---|---|---|
| `NormalizedResource` | `schema.py` | `resource_id` |
| `Rule` | `rule_engine.py` | `rule_id` |
| `Finding` | `schema.py` | `finding_id` |
| `AttackPath` | `attack_path/models.py` | `id` |
| `DriftEvent` | `drift/models.py` | `id` |
| `ResourceGraph` | `graph/models.py` | agrégat, scopé par `tenant_id` |

## 3. Value Objects (CURRENT CODE)

| VO | Fichier | Champs |
|---|---|---|
| `ResourceRelationship` | `schema.py` | `relationship_type`, `target_resource_id`, `source_field`, `properties` |
| `Evidence` | `value_objects.py` | `outcome`, `observed_attribute`, `expected_value`, `actual_value`, `operator`, `collector`, `collected_at`, `indeterminate_reason` |
| `RiskScore` | `value_objects.py` | `value` [0,100], `model_version`, `factors` |
| `ConfidenceScore` | `value_objects.py` | `value` [0,100], `model_version` |

## 4. Domain Services (CURRENT CODE)

| Service | Fichier | Rôle |
|---|---|---|
| `evaluate_condition_tree` | `conditions.py` | Évaluateur récursif AND/OR/NOT, logique à 3 états |
| `RuleEngine` | `rule_engine.py` | Charge les règles, orchestre l'évaluation, construit les `Finding` |
| `RiskCalculator` | `rule_engine.py` | Calcule `RiskScore`, modèle `crsf-1.1` |
| `GraphBuilder` | `graph/builder.py` | Construit `ResourceGraph` depuis les relations collectées |
| `PathDiscovery`, `PathConstraintEvaluator`, `AttackPathScorer`, `AttackTechniqueMapper`, `AttackPathAnalyzer` | `attack_path/*.py` | Découverte, contraintes, scoring, étiquetage, orchestration |
| `DiffEngine` | `drift/diff_engine.py` | Compare deux snapshots canonicalisés |

## 5. Exceptions

| Exception | Fichier | Déclenchée quand |
|---|---|---|
| `ConditionError` | `conditions.py` | Opérateur inconnu ou fonction contextuelle non enregistrée |
| `ValueError` (isolation tenant) | `graph/models.py` | Un nœud d'un autre tenant est ajouté au graphe |
| `ValueError` (Evidence) | `value_objects.py` | Cohérence `indeterminate_reason` violée (validation Pydantic) |

## 6. Invariants vérifiés par test

- Un attribut non collecté ne devient jamais silencieusement conforme
  (`ConditionOutcome.INDETERMINATE`, testé)
- Un chemin d'attaque bloqué par un contrôle de sécurité score 0, jamais
  retenu comme exploitable
- Un nœud de graphe d'un autre tenant est rejeté à la construction

## 7. Common Mistakes

**Technique** : confondre `Evidence` (value object structuré) avec un dict
libre — l'ancien modèle du projet (avant refactor) utilisait un dict à
trois formes différentes selon l'issue, source de bugs d'intégration
silencieux.

**Architecturale** : ajouter une dépendance infra dans `domain/` "juste pour
cette fois" — aucune trouvée aujourd'hui, à surveiller à chaque ajout futur.

**Sécurité** : construire une `Evidence` sans passer par la rédaction des
secrets avant projection externe (Anti-Corruption Layer, NOT IMPLEMENTED —
voir `13-decisions/architecture-decisions.md`).
