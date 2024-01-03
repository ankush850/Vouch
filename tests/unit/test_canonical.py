import pytest

from vouch.canonical import canonicalize, is_canonical


def test_key_ordering_is_deterministic():
    a = canonicalize({"b": 1, "a": 2, "c": 3})
    b = canonicalize({"c": 3, "b": 1, "a": 2})
    assert a == b
    assert a == b'{"a":2,"b":1,"c":3}'


def test_nested_structures_canonicalize_consistently():
    obj1 = {"outer": {"z": 1, "y": [3, 2, 1]}, "list": [{"b": 1, "a": 2}]}
    obj2 = {"list": [{"a": 2, "b": 1}], "outer": {"y": [3, 2, 1], "z": 1}}
    assert canonicalize(obj1) == canonicalize(obj2)


def test_mutation_changes_canonical_bytes():
    base = {"name": "bert-tiny", "version": "1.2.0", "seq": 14}
    mutated = {"name": "bert-tiny", "version": "1.2.0", "seq": 15}
    assert canonicalize(base) != canonicalize(mutated)


def test_no_insignificant_whitespace():
    out = canonicalize({"a": 1, "b": [1, 2, 3]})
    assert b" " not in out
    assert b"\n" not in out


def test_is_canonical_true_for_matching_bytes():
    obj = {"a": 1, "b": 2}
    assert is_canonical(obj, canonicalize(obj)) is True


def test_is_canonical_false_for_mismatched_bytes():
    assert is_canonical({"a": 1}, b'{"a": 1}') is False  # has a space; not canonical


def test_is_canonical_false_not_raises_for_integer_outside_jcs_safe_domain():
    # M4: rfc8785 raises its own ValueError subclass (IntegerDomainError)
    # for integers outside JCS's safe range rather than ever considering
    # them canonical -- found by parser fuzzing escaping as an unhandled
    # exception past every verify_*_envelope caller's existing
    # except-ValueError block, none of which wrapped canonicalize() itself.
    huge = 2**60
    with pytest.raises(ValueError):
        canonicalize(huge)
    assert is_canonical(huge, b"anything") is False
