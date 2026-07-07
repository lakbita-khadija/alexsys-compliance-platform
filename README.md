# Phase 1 — Infrastructure Cloud Sécurisée (IaC)

**Projet :** Plateforme Intelligente d'Audit de Conformité Cloud
**Couche d'architecture :** Couche 1 — Infrastructure Cloud (IaC)
**Référence cahier des charges :** Phase 1, Tâches 1.1 / 1.2 / 1.3 (Semaines 1-2)

> ⚠️ **Note sur le fournisseur cloud.** Le cahier des charges officiel v3.1, validé
> avec M. Jihad MAAROUF, cible **Microsoft Azure** comme cloud unique du MVP.
> Ce module contient en parallèle une **version d'entraînement personnelle sur AWS**,
> utilisée pour monter en compétence pendant que l'accès au sandbox Azure officiel
> n'est pas encore ouvert. Les deux pistes sont conceptuellement transposables
> (mêmes principes IaC/IAM/réseau/stockage/scan de sécurité) ; voir la section
> [Statut du provider cloud](#statut-du-provider-cloud) ci-dessous.

---

## Sommaire

- [Objectif de la phase](#objectif-de-la-phase)
- [Statut du provider cloud](#statut-du-provider-cloud)
- [Statut d'avancement](#statut-davancement)
- [Arborescence du dépôt](#arborescence-du-dépôt)
- [Prérequis](#prérequis)
- [Modules](#modules)
- [Écarts de sécurité volontaires](#écarts-de-sécurité-volontaires-findings-de-démonstration)
- [Gestion des secrets](#gestion-des-secrets)
- [Scan de sécurité (Checkov)](#scan-de-sécurité-checkov)
- [Commandes utiles](#commandes-utiles)
- [Correspondance ISO 27001 / Loi 05-20](#correspondance-iso-27001--loi-05-20-dnssi)
- [Checklist des livrables](#checklist-des-livrables-de-la-phase)
- [Risques connus](#risques-connus)
- [Contact](#contact)

---

## Objectif de la phase

Provisionner, via **Terraform** (Infrastructure as Code), un environnement
sandbox cloud représentatif — réseau, IAM, stockage, calcul — destiné à servir
de **cible d'audit** au futur Moteur de Scanning de Conformité (Phase 2).

Cette phase couvre trois livrables :

| Tâche | Description | Statut |
|---|---|---|
| **1.1** | Modules Terraform pour le sandbox (réseau, IAM, stockage, calcul), avec écarts de sécurité volontaires | 🔄 En cours |
| **1.2** | Gestion des secrets et des accès (`.gitignore`, `.env.example`, procédure de rotation) | 🔄 En cours |
| **1.3** | Scan de sécurité de l'infrastructure elle-même (Checkov) | ⏳ À venir |

---

## Statut du provider cloud

| Élément | Azure (périmètre officiel) | AWS (entraînement personnel) |
|---|---|---|
| Statut | Accès sandbox pas encore ouvert | Compte pas encore créé |
| Usage actuel | En attente de validation d'accès (Phase 0, Tâche 0.1) | Préparation théorique + code Terraform "à blanc" |
| Ce qui est déjà possible | — | Installation des outils, étude des concepts, écriture de modules, `terraform validate`/`plan`, scan Checkov statique |
| Ce qui attend un compte actif | `terraform apply`/`destroy` réels | `terraform apply`/`destroy` réels, `aws configure` |

**Approche retenue :** avancer sur tout ce qui ne nécessite pas de compte cloud actif
(théorie, structure du dépôt, code Terraform, exercices IAM en JSON, premier scan
Checkov sur du code statique), afin de ne pas perdre de temps en attendant les accès.

---

## Statut d'avancement

- [x] Étude des concepts réseau (VPC/VNet, subnets, IGW, NAT, security groups)
- [x] Étude des concepts IAM (users, groups, roles, policies, moindre privilège)
- [ ] Étude des concepts stockage (S3/Blob, chiffrement, accès public)
- [ ] Étude des concepts calcul (EC2/VM, security groups, volumes)
- [ ] Rédaction du module `network`
- [ ] Rédaction du module `iam`
- [ ] Rédaction du module `storage`
- [ ] Rédaction du module `compute`
- [ ] `.gitignore` et `.env.example`
- [ ] Documentation de la procédure de rotation des secrets
- [ ] Premier scan Checkov et rapport associé

*(À mettre à jour au fil de l'avancement réel.)*

---

## Arborescence du dépôt

```
infra/
├── modules/
│   ├── network/       # VPC/VNet, subnets, IGW/NAT, route tables, security groups
│   ├── iam/            # users, groups, roles, policies
│   ├── storage/        # bucket(s)/conteneur(s) — un sécurisé, un volontairement mal configuré
│   └── compute/        # instance(s) de calcul, security groups, volumes
├── environments/
│   └── sandbox/        # composition des modules pour l'environnement de démonstration
│       ├── main.tf
│       ├── variables.tf
│       └── outputs.tf
└── docs/
    ├── infra/
    │   └── README.md              # ce document
    └── security/
        ├── gestion-secrets.md     # procédure de rotation, .env.example documenté
        └── rapport-checkov-iac.md # résultats du scan de sécurité IaC
```

---

## Prérequis

| Outil | Version minimale | Nécessite un compte cloud ? |
|---|---|---|
| [Terraform](https://developer.hashicorp.com/terraform) | ≥ 1.5 | Non pour `init`/`validate`/`plan`/`fmt` — oui pour `apply`/`destroy` |
| [Checkov](https://www.checkov.io/) | dernière stable | Non — analyse statique du code uniquement |
| Git | toute version récente | Non |
| CLI du cloud provider (AWS CLI v2 / Azure CLI) | dernière stable | Non pour l'installation — oui pour `configure`/authentification |

Installation (exemple AWS) :

```bash
# Terraform
terraform -version

# AWS CLI v2
aws --version

# Checkov
pip install checkov --break-system-packages
checkov --version
```

---

## Modules

### `modules/network`
Provisionne le réseau : VPC/VNet, un subnet public et un subnet privé,
passerelle Internet, table de routage, security group(s) de base.

### `modules/iam`
Définit les identités et permissions : au moins un rôle en moindre privilège
et un rôle volontairement sur-permissif (finding de démonstration documenté).

### `modules/storage`
Deux ressources de stockage contrastées : une correctement sécurisée
(chiffrement activé, accès public bloqué, versioning activé) et une
volontairement mal configurée (à des fins de démonstration du futur scanner).

### `modules/compute`
Une instance de calcul minimale (type économique/gratuit), security group
restrictif, volume chiffré.

> Chaque module doit exposer des `variables.tf` et `outputs.tf` clairs,
> et être testable indépendamment via `terraform plan` dans un environnement
> dédié avant intégration dans `environments/sandbox/`.

---

## Écarts de sécurité volontaires (findings de démonstration)

Cette infrastructure sandbox est **intentionnellement imparfaite** : quelques
écarts de configuration réalistes sont introduits pour donner de vrais
résultats au Moteur de Scanning développé en Phase 2.

**Règle impérative :** chaque écart doit être commenté explicitement dans
le code Terraform, avec :
1. la raison de sa présence (finding pédagogique volontaire) ;
2. le contrôle ISO 27001 / Loi 05-20 concerné ;
3. une référence croisée vers `docs/security/rapport-checkov-iac.md`.

Exemple de convention de commentaire :

```hcl
# ⚠️ FINDING VOLONTAIRE — Ne pas corriger sans documentation.
# Ce security group autorise 0.0.0.0/0 sur le port 22.
# Objectif : fournir un cas de test réaliste au scanner de conformité (Phase 2).
# Contrôle concerné : ISO 27001 A.8.20 (sécurité réseau) / DNSSI - segmentation.
# Voir : docs/security/rapport-checkov-iac.md (finding CKV_AWS_24 accepté).
```

---

## Gestion des secrets

- Aucun identifiant (clé d'accès, mot de passe, token) ne doit apparaître en
  clair dans le code, les logs ou l'historique Git.
- `.env.example` est versionné (valeurs `REPLACE_ME`) ; `.env` réel est ignoré.
- Le fichier d'état Terraform (`*.tfstate`) n'est **jamais** commité — il peut
  contenir des données sensibles en clair.
- Procédure complète de rotation des clés : voir `docs/security/gestion-secrets.md`.
- Un scan de détection de secrets (type TruffleHog) doit être exécuté avant
  chaque commit majeur.

---

## Scan de sécurité (Checkov)

```bash
# Scan complet, sortie lisible dans le terminal
checkov -d infra/environments/sandbox --compact

# Export JSON (pour intégration ultérieure / archivage)
checkov -d infra/environments/sandbox -o json --output-file-path docs/security/

# Ignorer un finding précis, avec justification obligatoire dans le code
# checkov:skip=CKV_AWS_18:Bucket volontairement non journalisé — finding de démonstration
```

Chaque finding doit être classé en **corrigé** ou **accepté avec justification**
dans `docs/security/rapport-checkov-iac.md`. Aucun finding critique ne doit
rester sans décision documentée.

---

## Commandes utiles

```bash
# Initialiser un module ou un environnement
terraform init

# Vérifier la syntaxe et la cohérence du code (ne nécessite pas de compte cloud)
terraform validate

# Formater le code selon les conventions HCL
terraform fmt -recursive

# Prévisualiser les changements (nécessite des credentials valides pour un vrai plan distant)
terraform plan

# Appliquer / détruire (nécessite un compte cloud actif et configuré)
terraform apply
terraform destroy
```

---

## Correspondance ISO 27001 / Loi 05-20-DNSSI

| Domaine technique | Contrôle ISO/IEC 27001 (Annexe A) | Référence Loi 05-20 / DNSSI |
|---|---|---|
| Réseau (VPC, security groups) | A.8.20 – A.8.23 (sécurité des réseaux) | Exigences de segmentation réseau |
| IAM (moindre privilège) | A.5.15 – A.5.18 (contrôle d'accès) | Gestion des accès et des identités |
| Stockage (chiffrement, accès public) | A.8.24 (cryptographie), A.5.10 (gestion des actifs) | Protection des données au repos |
| Secrets et rotation | A.8.24, A.5.17 | Procédure de gestion des identifiants |
| Journalisation | A.8.15 (journalisation) | Traçabilité / auditabilité |

*(Correspondance indicative, à affiner avec la matrice officielle produite en
Phase 0, Tâche 0.2 — `docs/referentiels/mapping-controles.xlsx`.)*

---

## Checklist des livrables de la phase

- [ ] `infra/modules/network/`, `iam/`, `storage/`, `compute/` — 4 modules fonctionnels
- [ ] `infra/environments/sandbox/` — composition complète
- [ ] `docs/infra/README.md` — ce document, à jour
- [ ] `docs/security/gestion-secrets.md` — procédure de rotation documentée
- [ ] `.env.example` et `.gitignore` à jour, aucun secret dans l'historique Git
- [ ] `docs/security/rapport-checkov-iac.md` — rapport avec findings justifiés
- [ ] Écarts de sécurité volontaires commentés et tracés vers ISO 27001/Loi 05-20

---

## Risques connus

- **Retard d'accès au sandbox officiel** (Azure) : atténué en avançant sur la
  version d'entraînement AWS et sur toute la partie théorique/structurelle
  en parallèle.
- **Fichier d'état Terraform sensible** : mitigé par l'exclusion Git stricte
  et, à terme, un backend distant chiffré.
- **Dérive de périmètre** vers l'architecture cible complète : ce module reste
  volontairement limité aux tâches 1.1/1.2/1.3 telles que validées en Phase 0.

---

## Contact

| Rôle | Contact |
|---|---|
| Encadrant de stage — AlexSys Solutions | M. Jihad MAAROUF |
| Encadrant académique | Pr. Azougaghe Ali |
| Étudiante responsable (Couche 1 — IaC) | Khadija LAKBITA |
