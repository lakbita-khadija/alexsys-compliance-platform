"""``YamlRuleCatalog`` — the concrete ``LoadRuleCatalog`` port
implementation (blueprint §4, §9's "yaml loader" infrastructure row).

Its only responsibility is YAML -> ``Rule`` objects. It never evaluates
a rule (nothing here calls ``Rule.evaluate()``) and it never changes
the Domain's ``Rule`` contract to make parsing more convenient — a rule
definition that doesn't map cleanly onto ``Rule``'s existing fields
fails to load, loudly, rather than being coerced.

Expected YAML shape (one or more files in a directory, each with a
top-level ``rules:`` list). Only ``id``/``framework``/``control_id``/
``domain``/``severity``/``condition`` are required — every field below
that is optional catalog metadata (Phase 3B, Part F), each with the
same default ``Rule`` itself uses when the key is absent:

    rules:
      - id: s3-bucket-not-public
        framework: iso_27001
        control_id: A.8.24
        domain: storage
        severity: critical
        condition:
          field: public
          operator: equals
          value: true
        version: "1.0.0"
        title: "S3 bucket is publicly accessible"
        description: "..."
        service: s3
        confidence: high
        rationale: "..."
        evidence_template: "Bucket {resource_id} is public."
        references:
          - "https://docs.aws.amazon.com/..."
        tags: [s3, exposure]
        remediation:
          summary: "..."
          why_it_matters: "..."
          how_to_fix: "..."
          automation_example: "aws s3api ..."   # optional
        framework_mappings:
          - framework: cis_aws
            control: "1.20"
            status: verified   # or "unresolved" (the Rule default)

``condition`` is passed through to ``Rule`` completely unvalidated by
this loader — ``Rule``'s own constructor and
``domain.rules.conditions.evaluate_condition`` are the single source of
truth for what a valid condition looks like (ADR-004: validated at
evaluation time, not by a second parser here).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from application.rules.rule_catalog import LoadRuleCatalog
from domain.rules.rule import FrameworkMapping, Remediation, Rule
from domain.shared.enums import Confidence, Severity
from domain.shared.errors import InvalidRule, InvalidRuleCondition
from domain.shared.identifiers import InvalidIdentifier, RuleId
from infrastructure.rules.errors import RuleCatalogError


class YamlRuleCatalog(LoadRuleCatalog):
    """Loads every ``*.yaml``/``*.yml`` file in a directory into ``Rule``
    objects. File order is sorted for deterministic output.
    """

    def __init__(self, directory: str | Path) -> None:
        self._directory = Path(directory)

    def load(self) -> tuple[Rule, ...]:
        if not self._directory.is_dir():
            raise RuleCatalogError(f"rule catalog directory does not exist: {self._directory}")

        rules: list[Rule] = []
        for file_path in sorted(set(self._directory.glob("*.yaml")) | set(self._directory.glob("*.yml"))):
            rules.extend(self._load_file(file_path))
        return tuple(rules)

    def _load_file(self, file_path: Path) -> list[Rule]:
        try:
            data = yaml.safe_load(file_path.read_text())
        except yaml.YAMLError as exc:
            raise RuleCatalogError(f"malformed YAML in {file_path.name}: {exc}") from exc

        if data is None:
            return []
        if not isinstance(data, dict) or "rules" not in data:
            raise RuleCatalogError(f"{file_path.name} must have a top-level 'rules' key")

        raw_rules = data["rules"]
        if not isinstance(raw_rules, list):
            raise RuleCatalogError(f"{file_path.name}: 'rules' must be a list")

        return [self._parse_rule(entry, file_path) for entry in raw_rules]

    @staticmethod
    def _parse_rule(entry: dict, file_path: Path) -> Rule:
        try:
            remediation = YamlRuleCatalog._parse_remediation(entry.get("remediation"))
            framework_mappings = YamlRuleCatalog._parse_framework_mappings(entry.get("framework_mappings"))

            kwargs = dict(
                id=RuleId(entry["id"]),
                framework=entry["framework"],
                control_id=entry["control_id"],
                domain=entry["domain"],
                severity=Severity(entry["severity"]),
                condition=entry["condition"],
                remediation=remediation,
                framework_mappings=framework_mappings,
            )
            for field_name in (
                "version",
                "title",
                "description",
                "service",
                "rationale",
                "evidence_template",
                "applies_to_resource_type",
                # CSPM upgrade §27/§29. Optional, so a rule file written
                # before these existed loads unchanged.
                "category",
                "detection_logic",
                "false_positive_notes",
                "exceptions_supported",
            ):
                if field_name in entry:
                    kwargs[field_name] = entry[field_name]
            if "confidence" in entry:
                kwargs["confidence"] = Confidence(entry["confidence"])
            if "references" in entry:
                kwargs["references"] = tuple(entry["references"])
            if "tags" in entry:
                kwargs["tags"] = tuple(entry["tags"])

            return Rule(**kwargs)
        except KeyError as exc:
            raise RuleCatalogError(f"{file_path.name}: missing required field {exc}") from exc
        except ValueError as exc:
            raise RuleCatalogError(f"{file_path.name}: {exc}") from exc
        except (InvalidRule, InvalidRuleCondition, InvalidIdentifier) as exc:
            raise RuleCatalogError(f"{file_path.name}: {exc}") from exc

    @staticmethod
    def _parse_remediation(entry: dict | None) -> Remediation | None:
        if entry is None:
            return None
        return Remediation(
            summary=entry["summary"],
            why_it_matters=entry["why_it_matters"],
            how_to_fix=entry["how_to_fix"],
            automation_example=entry.get("automation_example"),
            verification=entry.get("verification"),
        )

    @staticmethod
    def _parse_framework_mappings(entries: list | None) -> tuple[FrameworkMapping, ...]:
        if entries is None:
            return ()
        mappings = []
        for entry in entries:
            kwargs = dict(framework=entry["framework"], control=entry["control"])
            # Each optional key is forwarded only when present, so a
            # mapping written before STEP 7 keeps `FrameworkMapping`'s
            # own defaults rather than being handed an explicit None.
            for optional in ("status", "version", "provenance", "rationale"):
                if optional in entry:
                    kwargs[optional] = entry[optional]
            mappings.append(FrameworkMapping(**kwargs))
        return tuple(mappings)
