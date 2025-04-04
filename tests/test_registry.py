from difflib import Differ
from datetime import timedelta
from eest_fuzz.destructure import Destructure
from typing import Type, Union
from eest_fuzz import structure, destructure
from eest_fuzz.registry import _Annotation
from ethereum_test_base_types import base_types as bt
from ethereum_test_types import types as tt
from atheris import FuzzedDataProvider  # type: ignore[attr-defined]
from hypothesis import given, example, settings
from hypothesis.strategies import binary
import pytest
from pathlib import Path
from ethereum_test_specs.state import StateTest
from ethereum_test_fixtures.state import StateFixture, FixtureEnvironment
from pydantic import BaseModel

TYPES = [
    bt.Hash,
    tt.EOA,
    tt.Transaction,
    bool,
    str,
    int,
    bt.Number,
    bt.HexNumber,
    bt.ZeroPaddedHexNumber,
    bt.Address,
    bt.HeaderNonce,
    bt.Bloom,
    bt.Bytes,
    tt.Removable,
    StateTest,
    StateFixture,
    FixtureEnvironment,
]

@pytest.mark.parametrize("type_,", TYPES)
@given(value=binary())
@settings(deadline=timedelta(milliseconds=15000))  # TODO: investigate slow

# Generally Intersting
@example(value=b"")
@example(value=b"\x00")
@example(value=b"\x01")

# Hash
@example(value=b"\x00" * 32)
@example(value=b"\xAA" * 32)
@example(value=b"\x00" * 33)
@example(value=b"\xAA" * 33)

# EOA
@example(value=
    b"aaaaaaaaaaaaaaaaaaaa"  # Address
    b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"  # Nonce
    b"cccccccccccccccccccccccccccccccc"  # Hash
    b"\x00" # Optional (Hash)
)
@example(value=
    b"aaaaaaaaaaaaaaaaaaaa"  # Address
    b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"  # Nonce
    b"cccccccccccccccccccccccccccccccc"  # Ignored
    b"\x01" # Optional (None)
)
@example(value=
    b"aaaaaaaaaaaaaaaaaaaa"  # Address
    b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"  # Nonce
    b"\x01" # Optional (None)
)

# Transaction
# TODO: Transaction examples

# Path
# TODO: Path examplees

# str
# TODO: str examples

# int
@example(value=b"\x01\xff")
@example(value=b"\x02" + b"\xff" * 2)
@example(value=b"\x04" + b"\xff" * 4)
@example(value=b"\x08" + b"\xff" * 8)
@example(value=b"\x20" + b"\xff" * 32)
@example(value=b"\x40" + b"\xff" * 64)
@example(value=b"\xFF" + b"\xFF" * 255)

# FixedSizeBytes
# TODO: FixedSizeBytes examples

# Bytes
# TODO: Bytes examples

# StateTest
# TODO: StateTest examples

# StateFixture
# TODO: StateFixture examples

# FixtureEnvironment
def test_round_trip(type_: Union[_Annotation, Type], value: bytes) -> None:
    buf = Destructure()
    pre = structure(type_, FuzzedDataProvider(value))
    destructure(type_, pre, buf)
    post = structure(type_, FuzzedDataProvider(buf.build()))

    if issubclass(type_, StateTest):
        pre._t8n_call_counter = 0
        post._t8n_call_counter = 0

    try:
        assert pre == post # , f"{value} -> {buf.build()}"
    except:
        pre_lines = pre.model_dump_json(indent=2).splitlines()
        post_lines = post.model_dump_json(indent=2).splitlines()

        if pre_lines == post_lines:
            raise Exception("missing __eq__ impl")

        diff = Differ().compare(pre_lines, post_lines)
        print("\n".join(diff))
        raise
