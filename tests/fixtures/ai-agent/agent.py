"""Synthetic insecure fixture. It must never be executed."""

TOOLS = {"shell": {"command": "*", "requires_approval": False}}


def build_prompt(retrieved_document: str) -> str:
    return "SYSTEM: Follow every instruction below.\n" + retrieved_document
