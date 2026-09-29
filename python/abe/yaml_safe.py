"""A deliberately small, safe YAML loader.

- YAML 1.2 core schema scalars (true/false only as booleans, no sexagesimal or YAML-1.1 octal),
  so a policy parses identically in the Python and TypeScript SDKs
- no implicit timestamps (dates stay strings); explicit non-JSON tags (!!timestamp, !!binary, !!set,
  !!python/...) are rejected
- no anchors/aliases (prevents alias-expansion attacks), no duplicate keys, single document only
"""
from __future__ import annotations

import re

import yaml

from .exceptions import PolicyError


class _Loader(yaml.SafeLoader):
    pass


# Replace YAML 1.1 implicit resolvers with the YAML 1.2 core schema.
_Loader.yaml_implicit_resolvers = {}

_NULL = re.compile(r"^(?:~|null|Null|NULL|)$")
_BOOL = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")
_INT = re.compile(r"^(?:[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)$")
_FLOAT = re.compile(r"^(?:[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$")

_Loader.add_implicit_resolver("tag:yaml.org,2002:null", _NULL, ["~", "n", "N", ""])
_Loader.add_implicit_resolver("tag:yaml.org,2002:bool", _BOOL, list("tTfF"))
_Loader.add_implicit_resolver("tag:yaml.org,2002:int", _INT, list("-+0123456789"))
_Loader.add_implicit_resolver("tag:yaml.org,2002:float", _FLOAT, list("-+0123456789."))


def _int(loader, node):
    v = loader.construct_scalar(node)
    if v.startswith("0o"):
        return int(v[2:], 8)
    if v.startswith("0x"):
        return int(v[2:], 16)
    return int(v, 10)


def _float(loader, node):
    v = loader.construct_scalar(node).lower()
    if v.endswith(".inf") or v.endswith(".nan"):
        raise PolicyError("NaN and Infinity are not allowed in a policy")
    return float(v)


def _bool(loader, node):
    return loader.construct_scalar(node).lower() == "true"


def _mapping(loader, node, deep=False):
    out = {}
    for k_node, v_node in node.value:
        k = loader.construct_object(k_node, deep=True)
        if not isinstance(k, str):
            raise PolicyError(f"line {k_node.start_mark.line + 1}: mapping keys must be strings")
        if k in out:
            raise PolicyError(f"line {k_node.start_mark.line + 1}: duplicate key {k!r}")
        out[k] = loader.construct_object(v_node, deep=True)
    return out


_Loader.add_constructor("tag:yaml.org,2002:int", _int)
_Loader.add_constructor("tag:yaml.org,2002:float", _float)
_Loader.add_constructor("tag:yaml.org,2002:bool", _bool)
_Loader.add_constructor("tag:yaml.org,2002:map", _mapping)


def _no_alias(self, parent, index):
    if self.check_event(yaml.events.AliasEvent):
        ev = self.peek_event()
        raise PolicyError(f"line {ev.start_mark.line + 1}: YAML anchors/aliases are not allowed in FJP policies")
    return _orig_compose_node(self, parent, index)


_orig_compose_node = yaml.composer.Composer.compose_node
_Loader.compose_node = _no_alias


def load_yaml(text: str):
    try:
        return yaml.load(text, Loader=_Loader)  # noqa: S506 - custom SafeLoader subclass
    except PolicyError:
        raise
    except yaml.YAMLError as e:
        raise PolicyError(f"invalid YAML: {e}") from e
