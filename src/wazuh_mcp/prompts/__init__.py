"""MCP prompts - user-invoked IR playbooks with server-side context loading.

Each prompt handler runs obvious Wazuh queries at invocation time and
returns a single user-role message containing the pre-fetched context.
Claude arrives with data already on hand, no follow-up tool calls needed
for the gather phase.

Contract: handlers return a dict shaped like MCP's prompts/get response:
  {"messages": [{"role": "user", "content": {"type": "text", "text": "..."}}]}
"""

from __future__ import annotations

from typing import Any


def make_user_message(text: str) -> dict[str, Any]:
    return {
        "messages": [
            {
                "role": "user",
                "content": {"type": "text", "text": text},
            }
        ]
    }
