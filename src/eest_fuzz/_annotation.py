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

from ._utils import unpick_value_in_list
from .destructure import Destructure
from .fuzz import Fuzz
from types import UnionType
from typing import Type, Dict, TypeVar, TYPE_CHECKING, Union, get_origin, Tuple, List, Mapping, get_args, Sequence as TypingSequence, Any, Annotated
from atheris import FuzzedDataProvider  # type: ignore[attr-defined]
from pydantic import BaseModel
from typing_extensions import assert_type
from collections.abc import Sequence as CollectionsSequence, Mapping as CollectionsMapping
from struct import pack

if TYPE_CHECKING:
    from .registry import _Annotation

T = TypeVar("T", bound=BaseModel)

def structure(type_: Union["_Annotation", Type[T]], data: FuzzedDataProvider) -> T:
    from .registry import structure as registry_structure
    origin = get_origin(type_)
    if origin in (Union, UnionType):
        return _structure_union(origin, get_args(type_), data)
    elif origin in (tuple, Tuple):
        raise NotImplementedError()
    elif origin in (List, TypingSequence, list, CollectionsSequence):
        return _structure_list(origin, get_args(type_), data)
    elif origin in (Dict, Mapping, dict, CollectionsMapping):
        return _structure_dict(origin, get_args(type_), data)
    elif origin is Annotated:
        return registry_structure(get_args(type_)[0], data)
    elif type_ is Any:
        return None
    else:
        raise NotImplementedError(f"unsupported annotation {type_} ({origin})")


def destructure(type_: Union["_Annotation", Type[T]], instance: T, output: Destructure) -> None:
    from .registry import destructure as registry_destructure
    origin = get_origin(type_)
    if origin in (Union, UnionType):
        return _destructure_union(origin, get_args(type_), instance, output)
    elif origin in (tuple, Tuple):
        raise NotImplementedError()
    elif origin in (List, TypingSequence, list, CollectionsSequence):
        return _destructure_list(origin, get_args(type_), instance, output)
    elif origin in (Dict, Mapping, dict, CollectionsMapping):
        return _destructure_dict(origin, get_args(type_), instance, output)
    elif origin is Annotated:
        return registry_destructure(get_args(type_)[0], instance, output)
    elif type_ is Any:
        return None
    else:
        raise NotImplementedError(f"unsupported annotation {origin}")


def _structure_dict(origin, args, data: FuzzedDataProvider) -> dict:
    from .registry import structure as registry_structure
    result = {}
    for _ in range(data.ConsumeUInt(2)):
        key = registry_structure(args[0], data)
        value = registry_structure(args[1], data)
        result[key] = value
    return result


def _destructure_dict(origin, args, instance, output: Destructure) -> None:
    from .registry import destructure as registry_destructure
    output.write_head(pack("<H", len(instance)))
    for key, value in instance.items():
        registry_destructure(args[0], key, output)
        registry_destructure(args[1], value, output)


def _structure_list(origin, args, data: FuzzedDataProvider) -> list:
    from .registry import structure as registry_structure
    count = data.ConsumeUInt(2)
    return [registry_structure(args[0], data) for _ in range(count)]


def _structure_union(origin, args, data: FuzzedDataProvider):
    from .registry import structure as registry_structure
    return registry_structure(data.PickValueInList(list(args)), data)


def _destructure_union(origin, args, instance, output: Destructure) -> None:
    from .registry import destructure as registry_destructure
    found = None

    for index, arg in enumerate(args):
        matches = _matches(instance, arg)

        if found is not None:
            if matches:
                raise Exception("ambiguous union variant")
        elif matches:
            found = index

    if found is None:
        raise Exception("no matching union variant")

    unpick_value_in_list(found, len(args), output)
    registry_destructure(args[found], instance, output)


def _matches(instance, type_) -> bool:
    if isinstance(type_, type):
        return isinstance(instance, type_)
    return _matches_annotation(instance, type_)


def _matches_annotation(instance, ann) -> bool:
    origin = get_origin(ann)
    args = get_args(ann)

    while origin is Annotated:
        origin = get_origin(args[0])
        args = get_args(args[0])

    if origin in (Union, UnionType):
        return any(_matches(instance, cls) for cls in args)
    elif origin in (tuple, Tuple):
        # TODO: Check inner types
        return isinstance(instance, tuple)
    elif origin in (List, TypingSequence, list, CollectionsSequence):
        if not isinstance(instance, (List, TypingSequence, list, CollectionsSequence)):
            return False
        if len(instance) == 0:
            return True
        return _matches(instance[0], args[0])
    elif origin in (Dict, Mapping, dict):
        if not isinstance(instance, (Dict, Mapping, dict)):
            return False
        if len(instance) == 0:
            return True
        k, v = next(iter(instance.items()))
        return _matches(k, args[0]) and _matches(v, args[1])
    elif ann is Any:
        return True
    else:
        raise NotImplementedError(f"unsupported annotation {origin} ({ann})")


def _destructure_list(origin, args, instance, output: Destructure) -> None:
    from .registry import destructure as registry_destructure
    output.write_head(pack("<H", len(instance)))
    for item in instance:
        registry_destructure(args[0], item, output)
