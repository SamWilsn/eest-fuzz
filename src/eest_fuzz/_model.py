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

from .fuzz import Fuzz
from typing import Type, TypeVar
from .destructure import Destructure
from atheris import FuzzedDataProvider  # type: ignore[attr-defined]
from pydantic import BaseModel
from typing_extensions import assert_type

T = TypeVar("T", bound=BaseModel)

def structure(type_: Type[T], data: FuzzedDataProvider) -> T:
    from .registry import structure as registry_structure, destructure as registry_destructure
    args = {}
    for name, info in sorted(type_.model_fields.items()):
        if info.exclude:
            continue
        assert info.annotation is not None
        args[name] = registry_structure(info.annotation, data)
    return type_(**args)


def destructure(type_: Type[T], instance: T, output: Destructure) -> None:
    from .registry import destructure as registry_destructure
    for name, info in sorted(type_.model_fields.items()):
        if info.exclude:
            continue
        assert info.annotation is not None
        registry_destructure(info.annotation, getattr(instance, name), output)
