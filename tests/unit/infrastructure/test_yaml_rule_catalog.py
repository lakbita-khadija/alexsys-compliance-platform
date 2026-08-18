import pytest

from domain.rules.rule import Rule
from domain.shared.enums import Severity
from domain.shared.identifiers import RuleId
from infrastructure.rules.errors import RuleCatalogError
from infrastructure.rules.yaml_rule_catalog import YamlRuleCatalog

VALID_RULE_YAML = """
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
"""

SECOND_RULE_YAML = """
rules:
  - id: s3-bucket-not-encrypted
    framework: iso_27001
    control_id: A.8.24
    domain: storage
    severity: high
    condition:
      field: encrypted
      operator: equals
      value: false
"""


class TestYamlRuleCatalogValidLoading:
    def test_loads_a_single_rule(self, tmp_path) -> None:
        (tmp_path / "s3.yaml").write_text(VALID_RULE_YAML)
        rules = YamlRuleCatalog(tmp_path).load()
        assert len(rules) == 1
        rule = rules[0]
        assert isinstance(rule, Rule)
        assert rule.id == RuleId("s3-bucket-not-public")
        assert rule.framework == "iso_27001"
        assert rule.control_id == "A.8.24"
        assert rule.domain == "storage"
        assert rule.severity is Severity.CRITICAL
        assert rule.condition == {"field": "public", "operator": "equals", "value": True}

    def test_combines_rules_from_multiple_files(self, tmp_path) -> None:
        (tmp_path / "a_s3_public.yaml").write_text(VALID_RULE_YAML)
        (tmp_path / "b_s3_encryption.yaml").write_text(SECOND_RULE_YAML)
        rules = YamlRuleCatalog(tmp_path).load()
        assert len(rules) == 2
        assert {str(r.id) for r in rules} == {"s3-bucket-not-public", "s3-bucket-not-encrypted"}

    def test_multiple_rules_in_one_file(self, tmp_path) -> None:
        combined = "rules:\n" + "\n".join(
            f"""  - id: rule-{i}
    framework: iso_27001
    control_id: A.8.24
    domain: storage
    severity: low
    condition:
      field: public
      operator: equals
      value: true
"""
            for i in range(3)
        )
        (tmp_path / "many.yaml").write_text(combined)
        rules = YamlRuleCatalog(tmp_path).load()
        assert len(rules) == 3

    def test_empty_directory_yields_empty_catalog(self, tmp_path) -> None:
        rules = YamlRuleCatalog(tmp_path).load()
        assert rules == ()

    def test_file_with_empty_rules_list_is_valid(self, tmp_path) -> None:
        (tmp_path / "empty.yaml").write_text("rules: []\n")
        rules = YamlRuleCatalog(tmp_path).load()
        assert rules == ()

    def test_loading_never_evaluates_any_rule(self, tmp_path) -> None:
        # A loader whose job were "YAML -> evaluated result" would need
        # a resource to evaluate against; this constructor takes none.
        (tmp_path / "s3.yaml").write_text(VALID_RULE_YAML)
        import inspect

        assert "resource" not in inspect.signature(YamlRuleCatalog.load).parameters

    def test_loading_is_deterministic(self, tmp_path) -> None:
        (tmp_path / "a.yaml").write_text(VALID_RULE_YAML)
        (tmp_path / "b.yaml").write_text(SECOND_RULE_YAML)
        first = YamlRuleCatalog(tmp_path).load()
        second = YamlRuleCatalog(tmp_path).load()
        assert [str(r.id) for r in first] == [str(r.id) for r in second]


class TestYamlRuleCatalogInvalidInput:
    def test_malformed_yaml_syntax_fails_clearly(self, tmp_path) -> None:
        (tmp_path / "broken.yaml").write_text("rules:\n  - id: [unclosed\n")
        with pytest.raises(RuleCatalogError):
            YamlRuleCatalog(tmp_path).load()

    def test_missing_required_field_fails_clearly(self, tmp_path) -> None:
        (tmp_path / "missing.yaml").write_text(
            """
rules:
  - id: broken-rule
    framework: iso_27001
    control_id: A.8.24
    domain: storage
    condition:
      field: public
      operator: equals
      value: true
"""
        )
        with pytest.raises(RuleCatalogError):
            YamlRuleCatalog(tmp_path).load()

    def test_unknown_severity_value_fails_clearly(self, tmp_path) -> None:
        (tmp_path / "bad_severity.yaml").write_text(
            """
rules:
  - id: broken-rule
    framework: iso_27001
    control_id: A.8.24
    domain: storage
    severity: super-critical
    condition:
      field: public
      operator: equals
      value: true
"""
        )
        with pytest.raises(RuleCatalogError):
            YamlRuleCatalog(tmp_path).load()

    def test_missing_top_level_rules_key_fails_clearly(self, tmp_path) -> None:
        (tmp_path / "no_rules_key.yaml").write_text("not_rules:\n  - id: x\n")
        with pytest.raises(RuleCatalogError):
            YamlRuleCatalog(tmp_path).load()

    def test_nonexistent_directory_fails_clearly(self) -> None:
        with pytest.raises(RuleCatalogError):
            YamlRuleCatalog("/no/such/directory").load()

    def test_error_message_identifies_the_offending_file(self, tmp_path) -> None:
        (tmp_path / "broken.yaml").write_text("rules:\n  - id: [unclosed\n")
        with pytest.raises(RuleCatalogError, match="broken.yaml"):
            YamlRuleCatalog(tmp_path).load()


FULL_METADATA_RULE_YAML = """
rules:
  - id: s3-bucket-public
    framework: iso_27001
    control_id: A.8.24
    domain: storage
    severity: critical
    condition:
      field: public
      operator: equals
      value: true
    version: "2.1.0"
    title: "S3 bucket is publicly accessible"
    description: "Bucket ACL grants read/write to the AllUsers or AuthenticatedUsers group."
    service: s3
    confidence: high
    rationale: "Public buckets are a leading cause of AWS data breaches."
    evidence_template: "Bucket {resource_id} is public."
    references:
      - "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
    tags: [s3, exposure, data-protection]
    remediation:
      summary: "Block public access on the bucket."
      why_it_matters: "A public bucket can leak sensitive data to anyone on the internet."
      how_to_fix: "Enable S3 Block Public Access at the bucket or account level."
      automation_example: "aws s3api put-public-access-block --bucket my-bucket --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
    framework_mappings:
      - framework: cis_aws
        control: "1.20"
        status: verified
        provenance: "CIS AWS Foundations Benchmark v1.5.0, section 1.20"
      - framework: nist_800_53
        control: "AC-3"
"""


class TestYamlRuleCatalogMetadata:
    def test_full_metadata_is_parsed(self, tmp_path) -> None:
        (tmp_path / "s3.yaml").write_text(FULL_METADATA_RULE_YAML)
        rule = YamlRuleCatalog(tmp_path).load()[0]
        assert rule.version == "2.1.0"
        assert rule.title == "S3 bucket is publicly accessible"
        assert rule.service == "s3"
        assert rule.confidence.value == "high"
        assert rule.rationale.startswith("Public buckets")
        assert rule.evidence_template == "Bucket {resource_id} is public."
        assert rule.references == (
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        )
        assert rule.tags == ("s3", "exposure", "data-protection")

    def test_remediation_is_parsed(self, tmp_path) -> None:
        (tmp_path / "s3.yaml").write_text(FULL_METADATA_RULE_YAML)
        rule = YamlRuleCatalog(tmp_path).load()[0]
        assert rule.remediation is not None
        assert rule.remediation.summary == "Block public access on the bucket."
        assert rule.remediation.automation_example.startswith("aws s3api")

    def test_framework_mappings_are_parsed(self, tmp_path) -> None:
        (tmp_path / "s3.yaml").write_text(FULL_METADATA_RULE_YAML)
        rule = YamlRuleCatalog(tmp_path).load()[0]
        assert len(rule.framework_mappings) == 2
        assert rule.framework_mappings[0].framework == "cis_aws"
        assert rule.framework_mappings[0].status == "verified"
        assert rule.framework_mappings[1].status == "unresolved"

    def test_rule_without_metadata_gets_domain_defaults(self, tmp_path) -> None:
        (tmp_path / "s3.yaml").write_text(VALID_RULE_YAML)
        rule = YamlRuleCatalog(tmp_path).load()[0]
        assert rule.version == "1.0.0"
        assert rule.title == ""
        assert rule.remediation is None
        assert rule.framework_mappings == ()

    def test_invalid_confidence_value_fails_clearly(self, tmp_path) -> None:
        (tmp_path / "bad.yaml").write_text(
            """
rules:
  - id: broken-rule
    framework: iso_27001
    control_id: A.8.24
    domain: storage
    severity: high
    confidence: super-high
    condition:
      field: public
      operator: equals
      value: true
"""
        )
        with pytest.raises(RuleCatalogError):
            YamlRuleCatalog(tmp_path).load()

    def test_remediation_missing_required_subfield_fails_clearly(self, tmp_path) -> None:
        (tmp_path / "bad.yaml").write_text(
            """
rules:
  - id: broken-rule
    framework: iso_27001
    control_id: A.8.24
    domain: storage
    severity: high
    condition:
      field: public
      operator: equals
      value: true
    remediation:
      summary: "fix it"
"""
        )
        with pytest.raises(RuleCatalogError):
            YamlRuleCatalog(tmp_path).load()
