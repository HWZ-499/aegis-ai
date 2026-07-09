"""
DSL support package for declarative security rules.

This module contains:
- Pydantic models describing YAML rule schema.
- A small matching engine for line-based patterns.
- Adapters that expose DSL rules via the existing SecurityRule interface.
"""

from __future__ import annotations

from .dsl_adapter import DslRuleAdapter, load_dsl_rule_definitions, load_dsl_rules_for_language
from .rule_schema import DslPattern, DslRule

__all__ = [
    "DslPattern",
    "DslRule",
    "DslRuleAdapter",
    "load_dsl_rule_definitions",
    "load_dsl_rules_for_language",
]
