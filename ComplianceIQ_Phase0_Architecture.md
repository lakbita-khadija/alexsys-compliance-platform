# ComplianceIQ — PHASE 0
## Validation et consolidation de l'architecture

> **Portée de cet audit.** Les deux bases de code auditées sont celles produites
> au cours de cette session (`complianceiq-core`, 66 fichiers Python ;
> `ciq`/Scanner, 14 fichiers Python + 5 YAML). Elles ont été relues fichier par
> fichier. Aucun Terraform, Kubernetes, Vault, Kafka, module d'authentification
> ni couche API n'existe dans l'une ou l'autre : ces éléments figurent dans la
> pile technique visée, pas dans le code. L'audit ne peut porter que sur ce qui
> existe.

---

# 1. Évaluation architecturale exécutive

## 1.1 Le verdict

L'architecture décrite dans la consigne est **massivement sur-dimensionnée par
rapport à l'état réel du code et au temps disponible**. C'est le principal
risque du projet — bien avant tout choix technique.

État réel, mesuré :

| Capacité | État |
|---|---|
| Rule Engine déclaratif, 33 règles, 3 états | ✅ fonctionnel, testé |
| Catalogue de frameworks versionné | ✅ fonctionnel, testé |
| Mapping avec confiance/provenance/revue | ✅ modèle de domaine, non câblé |
| Coverage / Priority | ✅ moteurs corrects, **jamais alimentés par un scan réel** |
| Collecteurs AWS / Azure | ⚠️ écrits, **jamais exécutés** |
| Persistance PostgreSQL | ⚠️ écrite, **jamais exécutée** |
| **API, authentification, multi-tenant réel, dashboard** | ❌ **0 ligne** |
| Neo4j, Attack Path, Drift, Event Bus, Plugin Manager | ❌ **0 ligne** |
| Kafka, Kubernetes, Terraform, Vault, OTel, Prometheus | ❌ **0 ligne** |

Le document d'architecture existant (SAS, FR-01→17, NFR-01→14, ADRs) décrit
donc une plateforme dont **environ 20 % existe**. Ce n'est pas une critique du
document : c'est une architecture cible légitime. Le danger est de la confondre
avec un plan d'implémentation.

## 1.2 Ce que je conteste dans l'architecture existante

**Sur-ingénierie (à retirer du périmètre immédiat) :**

- **Kafka / RabbitMQ** — un scan produit quelques milliers d'événements par
  exécution, sur un seul processus. Un bus de messages résout un problème de
  découplage inter-services que tu n'as pas. Il ajoute une infrastructure à
  exploiter, une sémantique de livraison à maîtriser et des tests d'idempotence
  à écrire. **Verdict : NON, pas maintenant.** Un `EventBus` in-process avec la
  même interface suffit et laisse la porte ouverte.
- **Kubernetes** — aucune charge à orchestrer, aucun besoin de mise à l'échelle
  horizontale, un seul environnement. **Verdict : NON.** `docker compose` couvre
  le développement local et la démonstration.
- **Neo4j** — l'Attack Path est la seule capacité qui le justifie vraiment, et
  elle n'existe pas. Introduire une seconde base avant que la première ne
  fonctionne est une faute d'ingénierie. **Verdict : différer.**
- **Plugin Manager** — architecture d'extension sans extension à charger. Le
  `CollectorPort` remplit déjà ce rôle. **Verdict : redondant.**
- **Composite Rule Engine + Context Intelligence + Policy Intelligence comme
  trois moteurs distincts** — ce sont trois responsabilités d'un même moteur de
  règles. Trois classes valent mieux que trois « moteurs » avec leurs frontières,
  leurs contrats et leurs ADRs.
- **OCI, GCP** — ports d'extension, pas des livrables.

**Sous-ingénierie (le vrai danger) :**

- **Aucune authentification.** Le `tenant_id` est aujourd'hui un simple champ de
  données. Une plateforme de sécurité multi-tenant sans authentification n'est
  pas « incomplète », elle est fondamentalement non conforme à sa propre promesse.
- **Aucune persistance des findings.** Chaque scan repart de zéro : ni
  historique, ni drift, ni tendance, ni preuve d'audit possible. Toute la
  proposition de valeur « auditabilité » repose sur une couche inexistante.
- **La chaîne Finding → Mapping → Coverage n'est pas câblée.** C'est ta
  contribution académique annoncée, et c'est précisément le maillon absent.

## 1.3 Sur l'ambition commerciale

La consigne demande une architecture « vendable ». Sois lucide : ce qui sépare
ComplianceIQ d'un produit commercial n'est pas architectural, c'est
opérationnel — mappings réglementaires **vérifiés par des juristes**,
certification, SLA, support, conformité RGPD/CNDP du traitement lui-même. Aucune
quantité de Kafka ne comble cet écart. En revanche, une architecture modulaire
propre permet d'y arriver plus tard sans réécriture : c'est l'objectif réaliste.

---

# 2. Audit de l'architecture existante

## 2.1 Dépôt Core (`complianceiq-core`)

| Module | Couche | Qualité | Décision |
|---|---|---|---|
| `Framework`, `FrameworkVersion`, `Control`, `Requirement` | domain | Solide — version publiée immuable, dépréciation par `superseded_by` | **REUSE** |
| `FrameworkMapping`, `MappingEvidence` | domain | Solide — invariant : INFERRED ne peut atteindre APPROVED sans revue | **REUSE** |
| `CoverageCalculator` | domain | Solide — 3 métriques distinctes, cohérence garantie par construction | **REUSE** + câbler |
| `PriorityScorer` | domain | Correct — Strategy, score explicable | **REUSE** + câbler |
| `ComplianceAssessment` | domain | Solide — applicabilité et évaluation orthogonales | **REUSE** |
| Use cases catalogue + ports | application | Clean Architecture correcte | **REUSE** |
| `PostgresFrameworkRepository`, ORM, migration | infra | ⚠️ jamais exécuté | **REUSE** après vérification |
| `corpus_loader`, `framework_seeds` | infra | Aligné sur l'enum de l'AI Service, test de contrat | **REUSE** |
| `finding_contract_mapper` | adapters | ACL correcte | **REFACTOR** vers modèle unifié |
| `normalized_resource.py`, `rule.py`, `rule_engine.py`, `run_scan.py`, `connectors/`, `builtin_rules.py` | — | Réimplémentés en mieux par le Scanner | **DEPRECATE** |

## 2.2 Dépôt Scanner (`ciq`)

| Module | Qualité | Décision |
|---|---|---|
| `schema.py` | Pydantic v2, `frozen`, `extra="forbid"` — cohérent avec l'AI Service | **REUSE — canonique** |
| `rule_engine.py` | YAML déclaratif, évaluateur fermé sans `eval()`, **3 états** | **REUSE — canonique** |
| `rules/*.yaml` (33 règles, 5 domaines) | Externalisées, mapping porté par la règle | **REUSE** |
| `collectors/base.py` | Port + tolérance aux échecs partiels | **REUSE** |
| `collectors/aws_collector.py` | S3 + Security Groups + IAM ⚠️ jamais exécuté | **REUSE** après vérification |
| `collectors/mock_collector.py` | Fixtures calquées sur le Terraform de test | **REUSE** |
| `scan_service.py` | Orchestration + rapport agrégé | **REUSE — canonique** |

---

# 3. Matrice de duplication et de conflit

**Cinq concepts existent en double, dans des versions mutuellement
incompatibles.** C'est le problème n°1 à résoudre.

| Concept | Core | Scanner | Conflit | Source de vérité retenue |
|---|---|---|---|---|
| `NormalizedResource` | dataclass : `id`, `cloud`, `service`, `type`, `config` | Pydantic : `resource_id`, `cloud_provider`, `resource_type`, `attributes` | 🔴 Noms **et** types divergents | **Scanner** |
| `Rule` | dataclass, conditions codées en Python | Pydantic, YAML, `attribute/operator/value` | 🔴 Deux formats | **Scanner** |
| `Finding` | dataclass | Pydantic `frozen` | 🔴 | **Scanner** + champs de traçabilité |
| `RuleEngine` | booléen 2 états | 3 états (`matched`/`not_matched`/`indeterminate`) | 🔴 | **Scanner** |
| Orchestration | `run_scan.py` | `scan_service.py` | 🔴 | **Scanner** |
| Enums (`CloudProvider`, `Severity`, `RiskDomain`, `ComplianceStatus`) | ✅ | ✅ | 🟠 Valeurs identiques, modules distincts | **Fusion en un module** |
| Collecteur AWS | S3 seul | S3 + EC2 + IAM | 🟠 | **Scanner** |
| Collecteur Azure | Blob | absent | 🟢 | **Porter Core → Scanner** |

**Pourquoi le Scanner l'emporte** : ses trois choix structurants sont
objectivement supérieurs — règles externalisées (ajouter une règle n'exige pas
de recompiler), évaluation à trois états (un attribut non collecté n'est jamais
silencieusement « conforme »), Pydantic `extra="forbid"` (cohérent avec
l'architecture de l'AI Service de ta coéquipière). Ce n'est pas une préférence
de style.

**Aucun code n'est jeté sans raison** : ce qui passe en DEPRECATE l'est parce
qu'une implémentation strictement meilleure existe ailleurs.

---

# 4. Décision d'architecture

**Option retenue : D — Refactorer les deux, le Scanner devenant le socle.**

| | |
|---|---|
| **Conservé** | Scanner intégralement + couche Compliance Intelligence du Core |
| **Supprimé** | Modèles et moteurs dupliqués du Core (7 fichiers) |
| **Déprécié** | `run_scan.py`, `builtin_rules.py`, `connectors/` du Core |
| **Refactoré** | ACL contrat, connecteur Azure (format `config` → `attributes`), enums fusionnés |
| **Source de vérité unique** | `domain/` du dépôt fusionné |

**Définitions canoniques uniques** — une seule par concept, sans exception :

```
Tenant, CloudAccount, NormalizedResource, Rule, Evidence, Finding,
Scan, RiskScore, ConfidenceScore          → base Scanner
Framework, FrameworkVersion, ComplianceControl, Requirement,
FrameworkMapping, ComplianceAssessment, Coverage, Priority  → base Core
```

---

# 5. Architecture cible

## 5.1 Décision structurante : monolithe modulaire

| Critère | Monolithe modulaire | Microservices |
|---|---|---|
| Taille d'équipe | 1 développeur | ≥ 1 équipe par service |
| Coût opérationnel | 1 processus | N déploiements, N pipelines, observabilité distribuée |
| Transactions | ACID natif | Sagas, cohérence à terme |
| Débogage | Trace unique | Tracing distribué obligatoire |
| Évolution | Extraction possible plus tard | Retour arrière très coûteux |

**Verdict : monolithe modulaire, avec des frontières de modules suffisamment
strictes pour permettre l'extraction ultérieure.** Les microservices résolvent
un problème organisationnel (équipes indépendantes) que tu n'as pas. Les
adopter maintenant importerait tout leur coût sans aucun de leurs bénéfices.
C'est défendable devant un jury : c'est la position de Fowler, et celle de la
majorité des équipes qui ont dû faire marche arrière.

## 5.2 Architecture globale

```mermaid
flowchart TB
    subgraph EXT["Fournisseurs cloud"]
        AWS[AWS]
        AZ[Azure]
    end
    subgraph INFRA["Infrastructure — adaptateurs"]
        AWSC[AwsCollector<br/>boto3]
        AZC[AzureCollector<br/>azure-sdk]
        PGR[Repositories Postgres]
        CACHE[Redis]
    end
    subgraph APP["Application — use cases + ports"]
        UC1[RunScan]
        UC2[MapFindingToControls]
        UC3[CalculateCoverage]
        UC4[GetDashboard]
        PORTS[CollectorPort<br/>RepositoryPort]
    end
    subgraph DOM["Domaine — aucune dépendance framework"]
        NR[NormalizedResource]
        RE[RuleEngine 3 états]
        FB[FindingBuilder]
        RISK[RiskCalculator]
        FM[FrameworkMapping]
        COV[CoverageCalculator]
        PRI[PriorityScorer]
    end
    subgraph ADAPT["Adaptateurs — API"]
        API[FastAPI + JWT + RBAC]
        DTO[DTO de réponse]
    end
    AWS --> AWSC --> PORTS
    AZ --> AZC --> PORTS
    PORTS --> UC1 --> DOM
    DOM --> UC2 --> UC3
    UC1 --> PGR
    UC4 --> CACHE
    APP --> ADAPT
    API --> DASH[Dashboard]
    API --> AIS[AI Service — coéquipière]
```

**Direction des dépendances : vers l'intérieur, sans exception.** Le domaine
n'importe jamais `boto3`, `azure-*`, `fastapi`, `sqlalchemy`, `neo4j`, `redis`.
Pydantic est toléré dans le domaine — choix assumé, aligné sur l'AI Service :
c'est une bibliothèque de validation, pas un framework d'infrastructure.

## 5.3 Arborescence définitive

```
complianceiq/
├── domain/
│   ├── entities/          normalized_resource, rule, finding, scan,
│   │                      framework, control, framework_mapping,
│   │                      compliance_assessment, tenant
│   ├── value_objects/     enums, risk_score, confidence_score,
│   │                      mapping_confidence, applicability, identifiers
│   ├── services/          rule_engine, risk_calculator, coverage_calculator,
│   │                      priority_scorer, mapping_resolver
│   └── events/            événements de domaine (bus in-process)
├── application/
│   ├── ports/             collector_port, *_repository_port, event_bus_port
│   └── use_cases/         run_scan, map_finding, calculate_coverage,
│                          get_dashboard, manage_framework_catalog
├── adapters/
│   ├── api/               routers, dto, dependencies (auth), errors
│   └── mappers/           ai_service_contract
├── infrastructure/
│   ├── collectors/        aws/, azure/, mock/
│   ├── persistence/       postgres/, in_memory/
│   ├── cache/             redis
│   ├── security/          jwt, rbac, tenant_context
│   └── seed/              framework_seeds, corpus_loader
├── rules/                 *.yaml
├── migrations/            *.sql
└── tests/                 unit/ integration/ security/
```

Neuf répertoires de premier niveau, chacun avec une responsabilité unique. Pas
de dossier créé « au cas où ».

---

# 6. Multi-tenant et sécurité

## 6.1 Défense en profondeur

```
1. API           tenant_id extrait du JWT — JAMAIS du corps de requête
2. Auth          signature, expiration, révocation vérifiées
3. Autorisation  RBAC centralisé (une seule politique, pas de `if role` épars)
4. Use case      TenantContext obligatoire en paramètre, non optionnel
5. Repository    tout SELECT filtré par tenant_id, sans exception possible
6. PostgreSQL    Row-Level Security — filet de sécurité si (5) est contourné
7. Cache         clés préfixées tenant:{id}:
8. Événements    tenant_id obligatoire dans chaque payload
```

**Sur la RLS PostgreSQL : oui, à activer.** Elle coûte peu et protège contre la
seule faute qui compte vraiment ici — un `WHERE tenant_id` oublié dans une
requête. Se reposer uniquement sur la discipline du développeur, sur un produit
de sécurité multi-tenant, n'est pas défendable.

```sql
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON findings
  USING (tenant_id = current_setting('app.current_tenant')::uuid);
```

Le `TenantContext` positionne `app.current_tenant` à l'ouverture de session.

## 6.2 Credentials cloud — architecture

**Règle absolue : aucun credential cloud permanent en base.**

| Option | Verdict |
|---|---|
| Clés d'accès AWS en base (chiffrées) | ❌ Compromission de la base = compromission de tous les comptes clients |
| **AssumeRole avec ExternalId** | ✅ **Recommandé.** Le client crée un rôle en lecture seule dans SON compte, avec un ExternalId propre à son tenant. Nous ne stockons qu'un ARN + un ExternalId — aucun secret. Révocable par le client à tout instant. |
| Azure Service Principal | ✅ Équivalent : rôle `Reader`, secret dans un coffre, jamais en base applicative |
| Vault | 🟡 Justifié à l'échelle, pas au MVP |

L'ExternalId protège contre le *confused deputy* : sans lui, un tiers connaissant
ton ARN de rôle pourrait usurper l'accès à un compte client.

## 6.3 Où chaque mécanisme de sécurité vit

| Mécanisme | Emplacement |
|---|---|
| JWT, en-têtes de sécurité, CORS, limitation de débit | `adapters/api/` |
| RBAC, ABAC | `application/` (politique) + `adapters/api/` (application) |
| Isolation tenant | Toutes les couches (§6.1) |
| Validation d'entrée | Pydantic, à la frontière |
| Prévention injection SQL | Requêtes paramétrées, `infrastructure/persistence/` |
| Validation des règles YAML | `safe_load` + validation Pydantic, jamais `eval()` |
| Journal d'audit | `application/` — chaque use case journalise |
| Gestion des secrets | `infrastructure/security/` |
| Chiffrement au repos / en transit | Configuration de la base, TLS |

**Ne jamais journaliser** : mots de passe, jetons, clés d'API, secrets AWS/Azure,
réponses d'API complètes (elles peuvent contenir des secrets).

---

# 7. Modèle PostgreSQL

```sql
tenants(id, name, status, created_at)
users(id, tenant_id→tenants, email, password_hash, status)
roles(id, name)                      -- global
user_roles(user_id, role_id, tenant_id)
cloud_accounts(id, tenant_id, provider, account_ref, role_arn, external_id, status)
   -- role_arn + external_id uniquement : AUCUN secret

scans(id, tenant_id, started_at, completed_at, status, resources_count, errors)
resources(id, tenant_id, scan_id, provider, resource_id, resource_type,
          region, attributes JSONB, tags JSONB, collected_at)

rules(id, rule_id, version, domain, severity, definition JSONB, framework,
      control_id, benchmark_source, enabled)   -- global, versionné

findings(id, tenant_id, scan_id, resource_id, rule_id, rule_version,
         status, severity, risk_score, confidence_score, evidence JSONB,
         first_seen, last_seen, detected_at)
   UNIQUE(tenant_id, resource_id, rule_id)     -- idempotence
   INDEX(tenant_id, status), INDEX(tenant_id, risk_score DESC)

frameworks(id, code, name, jurisdiction)                    -- global
framework_versions(id, framework_id, version_label, status, published_at)
controls(id, framework_version_id, control_id, title, description)
framework_mappings(id, rule_id, framework_version_id, control_id,
                   mapping_type, confidence, source, evidence JSONB,
                   verification_status, reviewed_by, created_at)

compliance_assessments(id, tenant_id, finding_id, mapping_id, control_id,
                       applicability, status, assessed_at, version)
audit_logs(id, tenant_id, actor_id, action, target, correlation_id, at)
```

**Points structurants :** `UNIQUE(tenant_id, resource_id, rule_id)` sur
`findings` rend les scans idempotents (un rescan met à jour `last_seen` au lieu
de dupliquer). `rule_version` sur chaque finding garantit la reproductibilité
d'une évaluation historique. Le catalogue de frameworks est **global**, sans
`tenant_id` : ISO 27001 est identique pour tous. Partitionnement de `findings`
par tenant : uniquement si le volume l'exige — pas au MVP.

---

# 8. Redis — périmètre strict

| Usage | Verdict |
|---|---|
| Agrégations de dashboard (TTL court) | ✅ justifié |
| Limitation de débit | ✅ justifié |
| Clés d'idempotence, verrous de scan | ✅ justifié |
| Source de vérité pour findings/résultats de scan | ❌ **jamais** |

Toute clé porte le préfixe `tenant:{id}:`. Ce qui est dans Redis doit pouvoir
disparaître sans perte de données.

---

# 9. API

```
POST /api/v1/scans                        déclenche un scan
GET  /api/v1/scans/{id}                   état
GET  /api/v1/findings                     filtres: severity, status, provider
GET  /api/v1/findings/{id}
GET  /api/v1/frameworks
GET  /api/v1/frameworks/{id}/coverage
GET  /api/v1/dashboard/overview
```

Toutes : JWT obligatoire, scope tenant issu du jeton, pagination, DTO de réponse
(jamais d'entité de domaine exposée), erreurs au format enveloppe unique,
`correlation_id` propagé.

---

# 10. Matrice de décision technologique

| Techno | Rôle | Maintenant | Justification |
|---|---|---|---|
| FastAPI | API | ✅ | Async, OpenAPI natif, Pydantic |
| PostgreSQL | Vérité transactionnelle | ✅ | ACID, JSONB, RLS |
| Pydantic | Validation | ✅ | Frontières typées, cohérent avec l'AI Service |
| Docker Compose | Environnement local | ✅ | Suffisant |
| Redis | Cache, limitation de débit | 🟡 Phase tardive | Utile, non bloquant |
| Neo4j | Graphe | ❌ Différer | Justifié par l'Attack Path, qui n'existe pas |
| Kafka / RabbitMQ | Bus | ❌ Non | Un `EventBus` in-process suffit à cette échelle |
| Kubernetes | Orchestration | ❌ Non | Aucune charge à orchestrer |
| Terraform | Infra de test | 🟡 Déjà présent | Garder pour créer des ressources mal configurées |
| Vault | Secrets | ❌ Différer | Variables d'environnement + coffre cloud au MVP |
| OTel / Prometheus / Grafana | Observabilité | 🟡 Phase tardive | Logs structurés d'abord |

---

# 11. Règles d'aptitude architecturale (à faire vérifier par la CI)

```
1.  domain/ n'importe ni boto3, ni azure-*, ni fastapi, ni sqlalchemy,
    ni neo4j, ni redis                              → import-linter
2.  Aucune méthode de repository sans tenant_id     → test dédié
3.  Aucun secret dans Git                           → gitleaks
4.  Aucun credential cloud permanent en base        → revue de schéma
5.  Chaque événement porte un tenant_id             → test
6.  Chaque finding porte rule_version + evidence    → test
7.  Chaque endpoint API exige une autorisation      → test
8.  Le tenant_id ne vient jamais du corps de requête → test de sécurité
9.  Aucun eval() / exec() dans le moteur de règles  → ruff
10. Tenant A ne peut pas lire les données de Tenant B → test non contournable
```

---

# 12. Feuille de route

L'ordre ci-dessous **diffère de celui proposé dans la consigne**, pour une
raison : la consigne place l'API en phase 12 et le multi-tenant en phase 11.
Concrètement, cela signifie construire dix couches avant de pouvoir démontrer
quoi que ce soit à qui que ce soit — et avant que ta coéquipière puisse
consommer une seule donnée. C'est le meilleur moyen de découvrir tard des
incompatibilités d'intégration.

| Phase | Contenu | Pourquoi à ce moment |
|---|---|---|
| **0** | Vérifier l'existant : Pydantic réel, `moto`, Postgres | 1 h — transforme « écrit » en « prouvé » |
| **1** | **Unifier les modèles** (un seul `Finding`, `Rule`, `NormalizedResource`) | Tout le reste se construit dessus |
| **2** | Fusion en un dépôt unique, Scanner comme socle | Cohérence |
| **3** | **Persistance Postgres** des scans/ressources/findings | Sans elle, aucun historique, aucune preuve |
| **4** | **API FastAPI** + JWT + scope tenant | Débloque l'intégration ET la démonstration |
| **5** | **Câblage Finding → Mapping → Coverage/Priority** | Ta contribution académique |
| **6** | RBAC + RLS + tests de sécurité | Avant toute exposition |
| **7** | Collecteur Azure | Preuve multi-cloud, coût faible |
| **8** | Dashboard backend | Ce que le jury regarde |
| **9** | Observabilité, durcissement | Si le temps le permet |
| — | Neo4j, Attack Path, Drift, Kafka, K8s, ABAC, GCP/OCI | **Travaux futurs assumés** |

---

# 13. Barre de qualité — évaluation honnête

| Critère | Note | Faiblesse principale |
|---|---|---|
| Maturité architecturale | **6/10** | Bonnes fondations, mais 5 modèles dupliqués et 3 couches absentes |
| Maturité sécurité | **2/10** | Aucune authentification, aucune autorisation, aucune gestion de secrets |
| Maturité multi-tenant | **2/10** | `tenant_id` n'est qu'un champ ; un seul garde applicatif |
| Maturité CSPM | **6/10** | Moteur de règles solide ; collecteurs jamais exécutés |
| Maturité cloud-native | **3/10** | Aucun déploiement, aucune observabilité |
| Maturité conformité | **5/10** | Modèle de mapping excellent, mais mappings non vérifiés et non câblés |
| Scalabilité | **4/10** | Aucune persistance, aucun traitement asynchrone |
| Maintenabilité | **7/10** | Clean Architecture correcte, bonne couverture de tests |
| Testabilité | **7/10** | 77 tests, mais exécutés avec un substitut de Pydantic |
| Maturité commerciale | **2/10** | Mappings non vérifiés juridiquement, aucune authentification |
| Défense académique | **6/10** | Trois contributions solides à défendre, périmètre trop large annoncé |

**Ce qui fait vraiment monter ces notes** : phases 3, 4 et 6. Pas Neo4j.

---

# 14. TOP 10 des risques avant implémentation

1. **Cinq modèles de domaine dupliqués et incompatibles** — bloque tout le reste.
2. **77 tests exécutés avec un substitut de Pydantic** — la logique est prouvée,
   mais ni `extra="forbid"`, ni `frozen`, ni la coercition de types.
3. **Collecteurs AWS/Azure jamais exécutés** — le cœur du produit n'a jamais
   touché un vrai cloud.
4. **Persistance Postgres jamais exécutée.**
5. **Aucune authentification** sur une plateforme de sécurité multi-tenant.
6. **Mappings réglementaires non vérifiés** — présenter `iso_27001/A.5.15` comme
   officiel sans confrontation au texte du standard est une faute grave pour un
   outil GRC, et un point sur lequel un jury peut légitimement attaquer.
7. **Coverage/Priority jamais alimentés par un scan réel.**
8. **Périmètre annoncé très supérieur au temps disponible** — risque de tout
   avoir à moitié.
9. **Aucune persistance des findings** → ni drift, ni tendance, ni audit.
10. **Dépendance à une intégration inter-équipes jamais testée de bout en bout.**

---

# 15. TOP 10 des décisions à ne plus changer après implémentation

1. Le Scanner comme socle, `domain/` unique source de vérité.
2. Règles déclaratives en YAML, jamais de code exécutable dans une règle.
3. Évaluation à **trois états** — ne jamais revenir à un booléen.
4. Le domaine n'importe aucun SDK cloud ni framework web.
5. `tenant_id` toujours issu de l'identité authentifiée.
6. PostgreSQL seule source de vérité transactionnelle.
7. Aucun credential cloud permanent en base — AssumeRole + ExternalId.
8. `Finding` immuable, versionné, portant `rule_version` et `evidence`.
9. Un mapping INFERRED ne devient jamais APPROVED sans revue humaine.
10. Coverage exposé en **trois métriques distinctes**, jamais en un pourcentage
    unique.

---

# 16. Première tâche exacte

**À faire par toi, avant toute écriture de code :**

```bash
# 1. Le vrai Pydantic — valide extra="forbid", frozen, coercition
cd ciq && pip install pydantic pyyaml pytest && pytest -v

# 2. Le collecteur AWS sous moto — AWS simulé, aucun compte requis
pip install moto boto3 && pytest tests/test_aws_collector_moto.py -v

# 3. Le repository Postgres
cd ../complianceiq-core && docker compose up -d postgres
psql postgresql://complianceiq:complianceiq@localhost:5432/complianceiq_core \
  -f migrations/0001_framework_catalog.sql
pip install -e ".[dev,postgres]" && pytest tests/integration -v -m integration
```

**Puis Phase 1, première tâche que j'exécuterai** : créer
`domain/entities/finding.py`, seul et unique `Finding` du projet, réconciliant
le modèle Pydantic du Scanner avec les champs de traçabilité (`scan_id`,
`rule_version`, `first_seen`, `last_seen`) exigés par l'auditabilité, puis
migrer les 77 tests existants dessus.

---

## Un dernier mot, franc

Ce document décrit une architecture cible cohérente et défendable. Mais la
qualité de ta soutenance ne dépendra pas de son exhaustivité : elle dépendra de
ta capacité à **faire tourner une chaîne complète devant le jury** et à
expliquer lucidement ce que tu n'as pas fait.

Un jury sanctionne bien plus durement une démonstration qui plante, ou un
mapping réglementaire présenté comme officiel sans preuve, qu'un périmètre
restreint mais tenu. Les phases 0 à 5 valent plus que les phases 6 à 19
réunies.
