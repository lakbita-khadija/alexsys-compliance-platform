"""Deterministic evidence narrative rendering (Phase 3B design proposal,
Part G: a finding must explain *why* a resource failed, not just that
it did).

``Rule.evidence_template`` (domain.rules.rule, optional, defaults to
``""``) is a plain ``str.format_map``-style template — never
``eval``/``exec``, never arbitrary code, just named placeholders drawn
from the resource's own already-collected attributes. Rendering is a
pure function of the template and the resource: the same rule and
resource always produce the same narrative text, no random wording.

Example:

    evidence_template: >
      Security group {resource_id} exposes port 22 to the internet
      (unrestricted_ingress_ports={unrestricted_ingress_ports}).

A placeholder referencing a field the resource doesn't have renders as
the literal ``{field_name}`` rather than raising — a missing field is
exactly the kind of thing evidence text should be able to say plainly,
not crash over.
"""

from __future__ import annotations

from domain.resources.models import NormalizedResource


class _SafeFormatDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def render_evidence(template: str, resource: NormalizedResource) -> str:
    """Render ``template`` against ``resource``'s attributes plus a
    handful of standard identity fields. Returns ``""`` unchanged if
    ``template`` is blank (the common case for rules that haven't been
    given a narrative yet).
    """

    if not template:
        return ""

    context = _SafeFormatDict(resource.attributes)
    context["resource_id"] = str(resource.resource_id)
    context["resource_type"] = resource.resource_type
    context["region"] = resource.region or "global"
    context["account_id"] = resource.account_id or "unknown"

    return template.format_map(context)
