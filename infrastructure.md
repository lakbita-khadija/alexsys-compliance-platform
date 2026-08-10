# Infrastructure

## 1. Overview

Contient les implémentations concrètes touchant l'extérieur du système :
les collecteurs cloud. C'est la **seule** couche du dépôt qui référence un
SDK externe (`boto3`, indirectement — voir §3).

## 2. Project Structure (réelle)

```text
collectors/
├── base.py               -- BaseCollector (interface), CollectionResult
├── mock_collector.py       -- MockAwsCollector : IMPLEMENTED, EXECUTED
└── aws_collector.py          -- AwsCollector : PARTIALLY IMPLEMENTED,
                                  NOT EXECUTED (pas de moto/boto3 dans
                                  l'environnement de rédaction)
```

`azure_collector.py` : **NOT IMPLEMENTED**.

## 3. AWS Collector — implémentation réelle

`AwsCollector.__init__(self, session, region)` — **injection de
dépendance** : reçoit une `boto3.Session` déjà construite, ne l'importe ni
ne la crée lui-même. Vérifié : `grep -rn "^import boto3\|^from boto3"
scanner/` ne retourne rien, y compris dans `aws_collector.py`.

Collecte : S3 (`_collect_s3`), Security Groups (`_collect_security_groups`),
IAM Users (`_collect_iam_users`). **NOT IMPLEMENTED** : RDS — documenté
explicitement dans le code lui-même (`_bucket_relationships`, commentaire
`MISSING COLLECTOR CAPABILITY`) : la relation `ALLOWS` security-group→RDS
existe dans `MockAwsCollector` mais le collecteur réel ne collecte même pas
les instances RDS.

Principe de collecte des attributs : `_safe()` retourne `None` sur tout
échec d'appel API — un attribut non lu est **omis**, jamais mis à `False`
par défaut (`_detect_public_access` documente explicitement : *"Ne jamais
transformer un échec en valeur False : ce serait rapporter une conformité
qu'on n'a pas vérifiée"*).

## 4. Dependencies

**Interne** : `scanner.schema` (`NormalizedResource`, enums),
`scanner.graph.models` (`INTERNET_NODE_ID`, pour la relation
`PUBLICLY_EXPOSED`).

**Externe** : `boto3.Session` (type hint uniquement, injectée) pour
`AwsCollector` ; aucune pour `MockAwsCollector`.

## 5. Testing

`MockAwsCollector` : couvert indirectement par tous les tests utilisant le
pipeline complet (`test_scan_service.py`, `test_graph.py`,
`test_attack_path.py`, `test_drift.py`).
`AwsCollector` : `tests/test_aws_collector_moto.py` (6 tests) — **écrit,
NON EXÉCUTÉ**.
