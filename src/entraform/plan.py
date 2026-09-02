"""Read a Terraform plan JSON into Resources.

We read `terraform show -json <plan>` output, not raw HCL. That is a deliberate robustness
choice: the plan JSON is a documented, stable contract (format_version, resource_changes[]),
whereas parsing HCL by hand means re-implementing interpolation, modules and variables and
getting them subtly wrong. The plan is what will actually be applied — so it is also the
honest thing to judge.
"""

from __future__ import annotations

import json

from .model import Resource


def load_resources(plan_json: str | dict) -> list[Resource]:
    data = json.loads(plan_json) if isinstance(plan_json, str) else plan_json
    if not isinstance(data, dict):
        raise ValueError("plan is not a JSON object")

    changes = data.get("resource_changes")
    if changes is None:
        # Some inputs are a raw state/config rather than a plan. Be explicit rather than
        # returning an empty list that reads as 'nothing to see here'.
        raise ValueError(
            "no 'resource_changes' in input — expected `terraform show -json <planfile>` "
            "output, not state or raw config"
        )

    resources: list[Resource] = []
    for rc in changes:
        change = rc.get("change") or {}
        actions = change.get("actions") or []
        # Skip pure deletes: a resource being destroyed is not a posture we are creating.
        if actions == ["delete"]:
            continue
        after = change.get("after")
        if after is None:
            continue
        resources.append(Resource(
            address=rc.get("address", "<unknown>"),
            type=rc.get("type", ""),
            after=after,
            provider=rc.get("provider_name", ""),
        ))
    return resources
