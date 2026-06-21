"""T14 — Deny-by-default topic policy (dialog rail L2).

Blocks requests matching a denied-topic pattern from a versioned policy file (the "denied topics"
control, cf. AWS Bedrock Guardrails). Policy lives in `topic_policy.json` next to this module so it
can be reviewed and version-bumped like code; a policy dict can also be injected for tests.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from core.rail import Decision, Rail, RailContext

DEFAULT_POLICY_PATH = Path(__file__).with_name("topic_policy.json")


class TopicPolicyRail(Rail):
    name = "topic_policy"

    def __init__(
        self, policy_path: str | Path | None = None, *, policy: dict[str, Any] | None = None
    ):
        if policy is None:
            policy = json.loads(Path(policy_path or DEFAULT_POLICY_PATH).read_text("utf-8"))
        self.version = str(policy.get("version", "0"))
        self.refusal = policy.get("refusal", "That topic is not permitted.")
        self._denied = [
            (d["name"], re.compile(d["pattern"], re.IGNORECASE))
            for d in policy.get("denied_topics", [])
        ]

    def inspect(self, ctx: RailContext) -> Decision:
        for name, rx in self._denied:
            if rx.search(ctx.text):
                return Decision.block(
                    f"{self.refusal} (denied topic: {name}; policy v{self.version})"
                )
        return Decision.allow()
