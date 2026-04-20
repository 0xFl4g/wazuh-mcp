import copy as _copy
import json
import logging
import pickle as _pickle

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from wazuh_mcp.secrets.value import SecretValue


def test_repr_does_not_leak():
    s = SecretValue("hunter2")
    assert "hunter2" not in repr(s)
    assert "<redacted>" in repr(s)


def test_str_does_not_leak():
    s = SecretValue("hunter2")
    assert "hunter2" not in str(s)


def test_expose_returns_plaintext():
    s = SecretValue("hunter2")
    assert s.expose() == "hunter2"


def test_json_dumps_refuses_to_serialize():
    s = SecretValue("hunter2")
    try:
        json.dumps({"pw": s})
    except TypeError:
        return
    raise AssertionError("SecretValue must not be JSON-serializable")


def test_log_formatter_does_not_leak(caplog):
    s = SecretValue("hunter2")
    logger = logging.getLogger("test_secret")
    with caplog.at_level(logging.INFO, logger="test_secret"):
        logger.info("value is %s", s)
    for rec in caplog.records:
        assert "hunter2" not in rec.getMessage()


def test_equality_by_value():
    assert SecretValue("a") == SecretValue("a")
    assert SecretValue("a") != SecretValue("b")


def test_hash_does_not_leak():
    s = SecretValue("hunter2")
    _ = hash(s)  # must not raise


@given(secret=st.text(min_size=1, max_size=200))
def test_redaction_property(secret):
    # Skip secrets that are substrings of the redaction template — those
    # appear in formatted output by coincidence, not by leaking plaintext.
    redaction_template = "SecretValue(<redacted>)"
    assume(secret not in redaction_template)

    s = SecretValue(secret)
    assert secret not in repr(s)
    assert secret not in str(s)
    assert secret not in format(s, "")
    assert secret not in f"{s}"
    assert secret not in f"{s!r}"


@pytest.mark.parametrize("bad", [123, None, b"bytes", ["list"], 1.5, object()])
def test_non_str_init_raises(bad):
    with pytest.raises(TypeError):
        SecretValue(bad)


def test_setattr_is_blocked():
    s = SecretValue("hunter2")
    with pytest.raises(AttributeError):
        s._value = "swap"
    with pytest.raises(AttributeError):
        s.new_attr = "x"


def test_delattr_is_blocked():
    s = SecretValue("hunter2")
    with pytest.raises(AttributeError):
        del s._value


def test_pickle_is_refused():
    s = SecretValue("hunter2")
    with pytest.raises(TypeError, match="not picklable"):
        _pickle.dumps(s)


def test_copy_preserves_opacity():
    s = SecretValue("hunter2")
    c = _copy.copy(s)
    assert c is not s
    assert c == s
    assert "hunter2" not in repr(c)
    assert c.expose() == "hunter2"


def test_deepcopy_preserves_opacity():
    s = SecretValue("hunter2")
    c = _copy.deepcopy(s)
    assert c is not s
    assert c == s
    assert "hunter2" not in repr(c)
    assert c.expose() == "hunter2"
