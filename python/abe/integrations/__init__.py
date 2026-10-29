"""Abe integrations for agent frameworks.

Each module turns Abe's ACT / BLOCK / ESCALATE into that framework's native control point.
None of them import the framework at module load, so the core package keeps its guarantees:
no network calls, no model calls, no extra dependencies.
"""
