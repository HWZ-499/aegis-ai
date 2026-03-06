"""
DSL support package for declarative security rules.

This module contains:
- Pydantic models describing YAML rule schema.
- A small matching engine for line-based patterns.
- Adapters that expose DSL rules via the existing SecurityRule interface.
"""

from __future__ import annotations

from .rule_schema import DslPattern, DslRule
from .dsl_adapter import DslRuleAdapter, load_dsl_rules_for_language

__all__ = [
    "DslPattern",
    "DslRule",
    "DslRuleAdapter",
    "load_dsl_rules_for_language",
]

