# eest-fuzz
# Copyright (C) 2025 Sam Wilson
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from .destructure import Destructure
from enum import Enum
from typing import get_origin, List
from .fuzz import Fuzz
from . import _model as model, _annotation as annotation, _enum
from typing_extensions import TypeAlias
from typing import Callable, TypeVar, Type, runtime_checkable, Protocol, Sequence, Union, Optional
from pydantic import BaseModel
from atheris import FuzzedDataProvider  # type: ignore[attr-defined]
from dataclasses import dataclass
from ethereum_test_base_types import base_types as bt
from ethereum_test_types import types as tt
from pathlib import Path
from ethereum_test_exceptions import engine_api as ea
from struct import pack
from ethereum_test_fixtures.state import StateFixture, FixtureForkPost, FixtureTransaction, AccessList


T = TypeVar("T", bound=BaseModel)
Q = TypeVar('Q')


@runtime_checkable
class _Annotation(Protocol):
    __metadata__: Sequence[object]
    __origin__: object


Spec: TypeAlias = Union[_Annotation, Type[T]]
StructureFunc: TypeAlias = Callable[[Union[_Annotation, Type[T]], FuzzedDataProvider], T]
DestructureFunc: TypeAlias = Callable[[Union[_Annotation, Type[T]], T, Destructure], None]


@dataclass
class _Codec:
    structure: StructureFunc
    destructure: DestructureFunc


_CODECS = {}


def register(type_: Spec, structure: StructureFunc, destructure: DestructureFunc):
    _CODECS[type_] = _Codec(structure=structure, destructure=destructure)


def _codec(type_: Spec) -> _Codec:
    try:
        return _CODECS[type_]
    except KeyError:
        pass

    if not isinstance(type_, type):
        return _Codec(structure=annotation.structure, destructure=annotation.destructure)

    if issubclass(type_, Fuzz):
        return _Codec(structure=type_.structure, destructure=lambda _, i, b: i.destructure(b))

    if issubclass(type_, Enum):
        return _Codec(structure=_enum.structure, destructure=_enum.destructure)

    if hasattr(type_, "model_fields"):
        return _Codec(structure=model.structure, destructure=model.destructure)

    raise ValueError(f"don't know how to (de)structure {type_}")


def structure(type_: Union[_Annotation, Type[T]], data: FuzzedDataProvider) -> T:
    impl = _codec(type_)
    return impl.structure(type_, data)


def destructure(type_: Union["_Annotation", Type[T]], instance: T, output: Destructure) -> None:
    impl = _codec(type_)
    impl.destructure(type_, instance, output)


def _structure_bytes(cls: Type, data: FuzzedDataProvider) -> bt.FixedSizeBytes:
    count = data.ConsumeUInt(2)
    return cls(data.ConsumeBytes(count))

def _destructure_bytes(type_: Union["_Annotation", Type[T]], instance: bytes, buf: Destructure) -> None:
    buf.write_head(pack("<H", len(instance)))
    buf.write_head(instance)

def _structure_fixed_size_bytes(cls: Type[bt.FixedSizeBytes], data: FuzzedDataProvider) -> bt.FixedSizeBytes:
    return cls(data.ConsumeBytes(cls.byte_length), left_padding=True)

def _destructure_fixed_size_bytes(type_: Union["_Annotation", Type[T]], instance: bt.FixedSizeBytes, buf: Destructure) -> None:
    buf.write_head(instance)

def _structure_eoa(cls: Type[tt.EOA], data: FuzzedDataProvider) -> tt.EOA:
    address = structure(bt.Address, data)
    nonce = structure(bt.Number, data)
    key = structure(Optional[bt.Hash], data)
    return cls(address, nonce=nonce, key=key)

def _destructure_eoa(type_: Union["_Annotation", Type[T]], instance: tt.EOA, buf: Destructure) -> None:
    destructure(tt.Address, tt.Address(instance), buf)
    destructure(tt.Number, instance.nonce, buf)
    destructure(Optional[tt.Hash], instance.key, buf)

def _structure_transaction(cls: Type[tt.Transaction], data: FuzzedDataProvider) -> tt.Transaction:
    args = {}

    ty = structure(bt.Number, data)
    args["ty"] = ty

    if ty <= 1:
        args["gas_price"] = structure(bt.Number, data)
    else:
        args["access_list"] = structure(List[tt.AccessList], data)

    if ty >= 2:
        args["max_fee_per_gas"] = structure(bt.Number, data)
        args["max_priority_fee_per_gas"] = structure(bt.Number, data)

    if ty == 3:
        args["max_fee_per_blob_gas"] = structure(bt.Number, data)

    if ty == 4:
        args["authorization_list"] = structure(List[tt.AuthorizationTuple], data)

    args["nonce"] = structure(bt.Number, data)

    for name, info in _tx_normal_fields(cls):
        assert info.annotation is not None
        args[name] = structure(info.annotation, data)

    return cls(**args)


def _destructure_transaction(type_: Union["_Annotation", Type[Q]], instance: Q, buf: Destructure) -> None:
    destructure(bt.Number, instance.ty, buf)

    if instance.ty <= 1:
        destructure(bt.Number, instance.gas_price, buf)
    else:
        destructure(List[tt.AccessList], instance.access_list, buf)

    if instance.ty >= 2:
        destructure(bt.Number, instance.max_fee_per_gas, buf)
        destructure(bt.Number, instance.max_priority_fee_per_gas, buf)

    if instance.ty == 3:
        destructure(bt.Number, instance.max_priority_fee_per_gas, buf)

    if instance.ty == 4:
        destructure(List[tt.AuthorizationTuple], instance.authorization_list, buf)

    destructure(bt.Number, instance.nonce, buf)
    for name, info in _tx_normal_fields(type_):
        assert info.annotation is not None
        destructure(info.annotation, getattr(instance, name), buf)


def _tx_normal_fields(cls: Type[tt.Transaction]):
    fields = dict(cls.model_fields)

    fields.pop('v', None)
    fields.pop('ty', None)

    fields.pop("gas_price", None)
    fields.pop("access_list", None)
    fields.pop("max_fee_per_gas", None)
    fields.pop("max_priority_fee_per_gas", None)
    fields.pop("max_fee_per_blob_gas", None)
    fields.pop("blob_versioned_hashes", None)
    fields.pop("authorization_list", None)
    fields.pop("nonce", None)

    return sorted(fields.items())


def _structure_string_like(cls: Callable[[str], Q], data: FuzzedDataProvider) -> Q:
    count = data.ConsumeUInt(1)
    buf = data.ConsumeUnicodeNoSurrogates(count)
    return cls(buf)


def _destructure_string_like(type_: Union["_Annotation", Type[Q]], instance: Q, buf: Destructure) -> None:
    encoded = instance.encode("utf-32le")
    buf.write_head(pack("<B", len(encoded) // 4))
    buf.write_head(b"\x00")  # string_spec
    buf.write_head(encoded)


def _structure_number(type_: Union["_Annotation", Type[Q]], data: FuzzedDataProvider) -> Q:
    size = data.ConsumeIntInRange(0, 32)
    return type_(data.ConsumeUInt(size))


def _destructure_number(type_: Union["_Annotation", Type[Q]], instance: Q, buf: Destructure) -> None:
    num = int(instance)
    byte_count = (num.bit_length() + 7) // 8
    buf.write_tail(pack("<B", byte_count))
    buf.write_head(num.to_bytes(byte_count, byteorder="little", signed=False))


def _structure_state_fixture(type_: Union["_Annotation", Type[Q]], data: FuzzedDataProvider) -> Q:
    count = data.ConsumeIntInRange(0, 5)

    args = {}
    for name, info in sorted(type_.model_fields.items()):
        if info.exclude:
            continue
        assert info.annotation is not None
        if name in ("post", "transaction"):
            continue
        args[name] = structure(info.annotation, data)

    post = []
    gas_limit = []
    value = []
    tx_data = []
    access_lists = []

    for _ in range(count):
        post.append(structure(FixtureForkPost, data))
        gas_limit.append(structure(bt.ZeroPaddedHexNumber, data))
        value.append(structure(bt.ZeroPaddedHexNumber, data))
        tx_data.append(structure(bt.Bytes, data))
        access_lists.append(structure(Optional[List[AccessList]], data))

    tx_args = {}
    for name, info in sorted(FixtureTransaction.model_fields.items()):
        if info.exclude:
            continue
        assert info.annotation is not None
        if name == 'gas_limit':
            tx_args[name] = gas_limit
        elif name == 'value':
            tx_args[name] = value
        elif name == 'data':
            tx_args[name] = tx_data
        elif name == 'access_lists':
            tx_args[name] = access_lists
        else:
            tx_args[name] = structure(info.annotation, data)

    args["transaction"] = FixtureTransaction(**tx_args)
    args["post"] = {"Prague": post}

    return type_(**args)



def _destructure_state_fixture(type_: Union["_Annotation", Type[Q]], instance: Q, buf: Destructure) -> None:
    buf.write_tail(pack("<B", len(instance.transaction.gas_limit)))

    for name, info in sorted(type_.model_fields.items()):
        if info.exclude:
            continue
        assert info.annotation is not None
        if name in ("post", "transaction"):
            continue
        destructure(info.annotation, getattr(instance, name), buf)

    for ii in range(len(instance.transaction.gas_limit)):
        destructure(FixtureForkPost, instance.post[ii], buf)
        destructure(bt.ZeroPaddedHexNumber, instance.transaction.gas_limit[ii], buf)
        destructure(bt.ZeroPaddedHexNumber, instance.transaction.value[ii], buf)
        destructure(bt.Bytes, instance.transaction.data[ii], buf)
        destructure(Optional[List[AccessList]], instance.transaction.access_lists[ii], buf)

    for name, info in sorted(FixtureTransaction.model_fields.items()):
        if info.exclude:
            continue
        assert info.annotation is not None
        if name in ('gas_limit', 'value', 'data'):
            continue
        destructure(info.annotation, getattr(instance.transaction, name), buf)



register(Path, _structure_string_like, _destructure_string_like)
register(str, _structure_string_like, _destructure_string_like)
register(bool, lambda _, data: data.ConsumeBool(), lambda _ty, i, o: o.write_head(b"\x01" if i else b"\x00"))
register(int, _structure_number, _destructure_number)
register(bt.Number, _structure_number, _destructure_number)
register(bt.HexNumber, _structure_number, _destructure_number)
register(bt.ZeroPaddedHexNumber, _structure_number, _destructure_number)
register(bt.Address, _structure_fixed_size_bytes, _destructure_fixed_size_bytes)
register(bt.Hash, _structure_fixed_size_bytes, _destructure_fixed_size_bytes)
register(bt.HashInt, _structure_number, _destructure_number)
register(bt.HeaderNonce, _structure_fixed_size_bytes, _destructure_fixed_size_bytes)
register(bt.Bloom, _structure_fixed_size_bytes, _destructure_fixed_size_bytes)
register(bt.Bytes, _structure_bytes, _destructure_bytes)
register(tt.EOA, _structure_eoa, _destructure_eoa)
register(tt.Transaction, _structure_transaction, _destructure_transaction)
register(tt.Removable, lambda cls, _: cls(), lambda _ty, _i, _o: None)
register(type(None), lambda _cls, _data: None, lambda _ty, _i, _o: None)
register(StateFixture, _structure_state_fixture, _destructure_state_fixture)
