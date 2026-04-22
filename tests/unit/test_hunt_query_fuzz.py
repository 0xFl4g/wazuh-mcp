"""Hypothesis property tests for hunt.hunt_query grammar safety."""

import string

from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from wazuh_mcp.tools.hunt import (
    FIELD_ALLOWLIST,
    OP_ALLOWLIST,
    HuntClause,
    HuntQueryArgs,
    _build_hunt_dsl,
)

# ---- Strategies ----

_OFF_ALLOWLIST_FIELDS = st.text(
    alphabet=string.ascii_letters + ".",
    min_size=1,
    max_size=64,
).filter(lambda s: s not in FIELD_ALLOWLIST)

_OFF_ALLOWLIST_OPS = st.text(
    alphabet=string.ascii_letters,
    min_size=1,
    max_size=20,
).filter(lambda s: s not in OP_ALLOWLIST)

_LEGAL_FIELDS = st.sampled_from(sorted(FIELD_ALLOWLIST))
_LEGAL_OPS = st.sampled_from(OP_ALLOWLIST)


@st.composite
def _legal_clause(draw):
    field = draw(_LEGAL_FIELDS)
    op = draw(_LEGAL_OPS)
    if op == "in":
        value = draw(st.lists(st.text(min_size=1, max_size=16), min_size=1, max_size=20))
    elif op == "exists":
        value = True
    elif op == "prefix":
        value = draw(st.text(min_size=3, max_size=32))
    elif op in ("gt", "gte", "lt", "lte"):
        value = draw(st.integers(min_value=0, max_value=15))
    else:
        value = draw(st.text(min_size=1, max_size=32))
    return HuntClause(field=field, op=op, value=value)


# ---- Helpers ----

_BANNED_KEYS = {"script", "runtime_mappings", "script_score", "painless"}


def _collect_keys(obj) -> set[str]:
    """Walk nested dict/list and collect all keys used at any depth."""
    out: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(str(k))
            out.update(_collect_keys(v))
    elif isinstance(obj, list):
        for item in obj:
            out.update(_collect_keys(item))
    return out


def _strip_source(dsl: dict) -> dict:
    """Return a shallow copy with `_source` replaced by None to avoid
    false positives from allowed _source field names containing substrings
    like 'description' -> 'script'."""
    copy = dict(dsl)
    copy["_source"] = None
    return copy


def _count_key_occurrences(obj, target: str) -> int:
    n = 0
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == target:
                n += 1
            n += _count_key_occurrences(v, target)
    elif isinstance(obj, list):
        for item in obj:
            n += _count_key_occurrences(item, target)
    return n


# ---- Properties ----


@given(field=_OFF_ALLOWLIST_FIELDS)
@settings(max_examples=200)
def test_any_off_allowlist_field_rejected(field):
    try:
        HuntClause(field=field, op="eq", value="x")
    except ValidationError:
        return
    raise AssertionError(f"allowlist bypass: {field!r}")


@given(op=_OFF_ALLOWLIST_OPS)
@settings(max_examples=100)
def test_any_off_allowlist_op_rejected(op):
    try:
        HuntClause(field="rule.id", op=op, value="x")  # type: ignore[arg-type]
    except ValidationError:
        return
    raise AssertionError(f"op allowlist bypass: {op!r}")


@given(
    must=st.lists(_legal_clause(), min_size=0, max_size=25),
    must_not=st.lists(_legal_clause(), min_size=0, max_size=25),
    time_range=st.sampled_from(["1h", "24h", "7d", "29d"]),
)
@settings(max_examples=200, deadline=None)
def test_any_legal_clause_combo_produces_safe_dsl(must, must_not, time_range):
    try:
        args = HuntQueryArgs(
            time_range=time_range,
            must=must,
            must_not=must_not,
        )
    except ValidationError:
        return  # oversize or empty-both-lists - validator did its job

    dsl = _build_hunt_dsl(args)
    keys = _collect_keys(_strip_source(dsl))
    leaked = keys & _BANNED_KEYS
    assert not leaked, f"DSL escape via keys: {leaked} in {dsl!r}"

    # No nested bool either - at most one `bool` key (the top-level one).
    # Count via the walker rather than str() substring to avoid _source noise.
    bool_count = _count_key_occurrences(_strip_source(dsl), "bool")
    assert bool_count <= 1, f"nested bool: {bool_count} occurrences"


@given(size=st.integers(min_value=-1000, max_value=10_000))
@settings(max_examples=50)
def test_size_always_in_range_or_rejected(size):
    try:
        args = HuntQueryArgs(
            time_range="24h",
            must=[HuntClause(field="rule.id", op="eq", value="1")],
            size=size,
        )
    except ValidationError:
        return
    assert 1 <= args.size <= 100


@given(in_list=st.lists(st.text(min_size=1, max_size=8), min_size=0, max_size=200))
@settings(max_examples=50)
def test_in_op_caps_list_length(in_list):
    try:
        HuntClause(field="rule.id", op="in", value=in_list)
    except ValidationError:
        return
    assert 1 <= len(in_list) <= 100
