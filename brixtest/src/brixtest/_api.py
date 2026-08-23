"""Stable API metadata facade and consistency checks."""

from __future__ import annotations

from brixtest._api_constructors import PUBLIC_CLASS_CALL_SHAPES
from brixtest._api_exports import PUBLIC_EXPORTS
from brixtest._api_exports import PUBLIC_GROUPS as PUBLIC_GROUPS
from brixtest._api_functions import PUBLIC_CALL_SHAPES
from brixtest._api_members import (
    PUBLIC_ATTRIBUTES,
    PUBLIC_MEMBER_CALL_SHAPES,
    PUBLIC_PROPERTIES,
)
from brixtest._api_methods import PUBLIC_METHODS

assert set(PUBLIC_CALL_SHAPES).isdisjoint(PUBLIC_METHODS), (
    "a BriXTest public name cannot be both a function and a class"
)
assert set(PUBLIC_CALL_SHAPES) | set(PUBLIC_METHODS) <= set(PUBLIC_EXPORTS), (
    "public callable contracts must refer to exported names"
)
assert set(PUBLIC_CLASS_CALL_SHAPES) == set(PUBLIC_METHODS), (
    "every BriXTest public class needs a constructor call shape"
)
assert set(PUBLIC_MEMBER_CALL_SHAPES) == {
    "%s.%s" % (owner, member) for owner, members in PUBLIC_METHODS.items() for member in members
}, "every BriXTest public class member needs a call shape"
assert set(PUBLIC_PROPERTIES) <= set(PUBLIC_METHODS) and all(
    set(properties) <= set(PUBLIC_METHODS[owner]) for owner, properties in PUBLIC_PROPERTIES.items()
), "public properties must be public class members"
assert set(PUBLIC_ATTRIBUTES) == set(PUBLIC_METHODS), (
    "every BriXTest public class needs an explicit readable-attribute contract"
)
assert all(
    set(PUBLIC_ATTRIBUTES[name]).isdisjoint(PUBLIC_METHODS[name]) for name in PUBLIC_METHODS
), "public attributes and callable/property members must not overlap"
