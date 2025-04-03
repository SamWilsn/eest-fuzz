from eest_fuzz.destructure import Destructure
from typing import Type, Union, Optional, List, Dict
from eest_fuzz._annotation import structure, destructure
from eest_fuzz.registry import _Annotation
from ethereum_test_base_types import base_types as bt
from ethereum_test_types import types as tt
from atheris import FuzzedDataProvider  # type: ignore[attr-defined]
from hypothesis import given, example
from hypothesis.strategies import binary
import pytest

TYPES = [
    Optional[bool],
    List[bool],
    Dict[bool, bool],
    Union[bool, List[bool], Dict[bool, bool]],
]

@pytest.mark.parametrize("type_,", TYPES)
@given(value=binary())

# Generally Interesting
@example(value=b"")
@example(value=b"\x00")
@example(value=b"\x01")

# Optional[bool]
@example(value=b"\x00\x00")
@example(value=b"\x00\x01")
@example(value=b"\x01\x00")
@example(value=b"\x01\x01")

# List[bool]
@example(value=b"\x00\x00")
@example(value=b"\x01\x00\x01")
@example(value=b"\x01\x00\x00")
@example(value=b"\x02\x00\x00\x00")
@example(value=b"\x02\x00\x01\x00")
@example(value=b"\x02\x00\x01\x01")
@example(value=b"\x02\x00\x00\x01")

# Dict[bool, bool]
@example(value=b"\x01\x00\x00\x00")
@example(value=b"\x01\x00\x01\x00")
@example(value=b"\x01\x00\x00\x01")
@example(value=b"\x01\x00\x01\x01")
@example(value=b"\x02\x00\x01\x01\x01\x01")
@example(value=b"\x02\x00\x01\x01\x00\x01")

# Union[bool, List[bool], Dict[bool, bool]]
@example(value=b"\x05\x00\x00\x01\x00\x01\x00\x01") # [False, True, False, True, False]
@example(value=b"\x02\x00\x01\x01\x00\x00\x02") # {True: True, False: False}
@example(value=b"\x02\x00\x01\x01\x00\x00\x03") # Invalid

def test_round_trip(type_: Union[_Annotation, Type], value: bytes) -> None:
    buf = Destructure()
    pre = structure(type_, FuzzedDataProvider(value))
    destructure(type_, pre, buf)
    new_value = buf.build()
    post = structure(type_, FuzzedDataProvider(new_value))
    assert pre == post, f"{value} -> {new_value}"
