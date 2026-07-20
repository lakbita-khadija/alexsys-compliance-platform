"""
scanner/schema.py — v1.2.0

LE SCHÉMA PARTAGÉ — source unique de vérité pour la forme des données.
Toute modification ici nécessite une conversation entre Student A et Student B,
jamais un edit solo (voir Compass, Part 10 & 11).

Changements depuis v1.1.0 :
- Finding.domain devient OBLIGATOIRE (reflète l'usage réel : toutes les règles
  écrites à ce jour assignent un domaine).
- Finding.status ajouté (FindingStatus : open / resolved / dismissed).
- FinancialRiskAssessment.citation ajouté (référence structurée vers
  RegulatoryCitation, pour tracer la base légale d'un montant).
- ComplianceScore.score_by_framework renommé score_by_domain (plus utile :
  correspond directement au découpage dashboard A/B).
- CloudProvider.TERRAFORM_PLAN conservé (Compliance Simulation, roadmap S10).
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums — vocabulaire fermé, partagé par les 3 clouds
# ---------------------------------------------------------------------------

class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    TERRAFORM_PLAN = "terraform_plan"  # Compliance Simulation — pas encore déployé


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class ComplianceStatus(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non-compliant"
    MIXED = "mixed"


class Domain(str, Enum):
    """Domaine de règle — permet de filtrer par onglet dashboard (A: iam/network, B: encryption/logging/storage)."""
    IAM = "iam"
    NETWORK = "network"
    ENCRYPTION = "encryption"
    LOGGING = "logging"
    STORAGE = "storage"


# ---------------------------------------------------------------------------
# 1. NormalizedResource — ce que produisent les connecteurs AVANT le rule engine
# ---------------------------------------------------------------------------

class NormalizedResource(BaseModel):
    """Une ressource cloud unique, peu importe son fournisseur d'origine."""

    cloud_provider: CloudProvider
    resource_id: str = Field(..., description="Identifiant unique de la ressource (bucket name, SG id, ARN...)")
    resource_type: str = Field(..., description="ex: s3_bucket, security_group, iam_user, storage_bucket...")
    region: Optional[str] = None
    tags: dict[str, str] = Field(default_factory=dict)

    # Attributs bruts spécifiques au type de ressource — volontairement
    # flexible (dict) pour ne pas exploser le schéma à chaque nouveau type
    # de ressource. Les règles savent quels attributs lire selon resource_type.
    attributes: dict = Field(default_factory=dict)

    collected_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# 2. Finding — ce que produit le RULE ENGINE (le contrat central du projet)
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """Un problème de conformité détecté sur UNE ressource."""

    id: Optional[str] = Field(default=None, description="UUID généré côté backend/DB, absent à la détection")
    cloud_provider: CloudProvider
    resource_id: str
    resource_type: str
    rule_id: str = Field(..., description="ex: s3.encryption_disabled, ec2.sg_open_to_world")
    domain: Domain = Field(..., description="Filtrage par onglet dashboard — iam/network (A) vs encryption/logging/storage (B). Obligatoire depuis v1.2.0.")
    severity: Severity
    description: str = Field(..., max_length=2000)
    status: FindingStatus = Field(default=FindingStatus.OPEN)
    detected_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Utilisé par la Compliance Simulation (avant déploiement réel)
    simulated: bool = Field(default=False, description="True si issu d'un terraform plan, pas d'un scan réel")

    # Utilisé par la corrélation de risques (S8) — None si le finding est isolé
    correlation_id: Optional[str] = Field(None, description="Référence vers CorrelatedRisk si ce finding fait partie d'une combinaison")

    @field_validator("resource_id", "rule_id")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("ne peut pas être vide")
        return v


# ---------------------------------------------------------------------------
# 3. CorrelatedRisk — sortie de la corrélation de risques (S8)
# ---------------------------------------------------------------------------

class CorrelatedRisk(BaseModel):
    """Une combinaison de findings dont le risque combiné dépasse la somme des parties."""

    correlation_id: str
    finding_ids: list[str] = Field(..., min_length=2, description="Au moins 2 findings corrélés")
    combined_severity: Severity
    narrative: str = Field(..., description="Explication en langage naturel de la chaîne de risque (attack path)")


# ---------------------------------------------------------------------------
# 4. EnrichedFinding — sortie du RAG pipeline / finding linker (citation vérifiée)
# ---------------------------------------------------------------------------

class RegulatoryCitation(BaseModel):
    """Une citation vérifiée — jamais générée sans preuve dans le corpus."""

    framework: str = Field(..., description="ex: 'ISO 27001', 'Loi 09-08', 'DNSSI'")
    article_or_control: str = Field(..., description="ex: 'Annexe A.8.24', 'Article 55'")
    excerpt: str = Field(..., max_length=3000, description="Extrait exact du corpus source, jamais paraphrasé sans le dire")
    source_document_id: str


class EnrichedFinding(BaseModel):
    """Un Finding enrichi par le copilot IA : explication + citation vérifiée."""

    finding: Finding
    explanation: str = Field(..., max_length=5000)
    citations: list[RegulatoryCitation] = Field(default_factory=list)
    citation_verified: bool = Field(..., description="False → le copilot doit dire 'je ne sais pas', jamais deviner")


# ---------------------------------------------------------------------------
# 5. FinancialRiskAssessment — sortie du Financial Risk Translator (A6)
# ---------------------------------------------------------------------------

class FinancialRiskAssessment(BaseModel):
    """Traduction d'un finding (ou d'un risque corrélé) en exposition financière."""

    finding_id: Optional[str] = None
    correlation_id: Optional[str] = None
    estimated_min_mad: float = Field(..., ge=0)
    estimated_max_mad: float = Field(..., ge=0)
    rationale: str = Field(..., max_length=2000)
    citation: Optional[RegulatoryCitation] = Field(
        None, description="Base légale du montant estimé (ex: Loi 09-08 art. 55-56), quand applicable"
    )

    @field_validator("estimated_max_mad")
    @classmethod
    def max_gte_min(cls, v: float, info) -> float:
        min_val = info.data.get("estimated_min_mad")
        if min_val is not None and v < min_val:
            raise ValueError("estimated_max_mad doit être >= estimated_min_mad")
        return v


# ---------------------------------------------------------------------------
# 6. RemediationProposal — sortie du générateur de remédiation
#    Réutilise le RAG pour la justification (Student B) sur une correction
#    proposée par Student A. JAMAIS exécutée automatiquement — approval
#    humain obligatoire (voir narratif "agent" du document maître).
# ---------------------------------------------------------------------------

class RemediationProposal(BaseModel):
    """Une proposition de correction Terraform pour un finding donné."""

    finding_id: str
    terraform_snippet: str = Field(..., description="Code Terraform proposé — jamais appliqué automatiquement")
    justification: str = Field(..., description="Explication en langage naturel de pourquoi ce fix résout le problème")
    justification_citation: Optional[RegulatoryCitation] = Field(
        None, description="La citation exacte que ce fix permet de satisfaire"
    )
    approved: bool = Field(default=False, description="Validation humaine requise avant toute application réelle")
    approved_by: Optional[str] = None
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# 7. ExploitProof — sortie du Red-Team Proof Engine
#    Miroir du dataclass ProofResult (proof_engine.py), pour que le
#    frontend/mobile puisse l'afficher via l'API sans transformation ad-hoc.
# ---------------------------------------------------------------------------

class ExploitProof(BaseModel):
    """Preuve d'exploitabilité d'un finding, générée UNIQUEMENT sur le sandbox tagué."""

    finding_rule_id: str
    resource_id: str
    exploited: bool
    narrative: str
    evidence: dict = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# 8. ComplianceScore — agrégation finale affichée au dashboard
# ---------------------------------------------------------------------------

class ComplianceScore(BaseModel):
    overall_score: float = Field(..., ge=0, le=100)
    score_by_domain: dict[str, float] = Field(default_factory=dict, description="ex: {'iam': 78.0, 'encryption': 65.0} — remplace score_by_framework depuis v1.2.0")
    score_by_cloud: dict[CloudProvider, float] = Field(default_factory=dict)
    total_findings: int
    critical_findings: int
    computed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
