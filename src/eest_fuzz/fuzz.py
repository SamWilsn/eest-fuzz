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

from typing_extensions import Self
from typing import Protocol, runtime_checkable, Type
from atheris import FuzzedDataProvider  # type: ignore[attr-defined]
from .destructure import Destructure


@runtime_checkable
class Fuzz(Protocol):
    @classmethod
    def structure(type_: Type[Self], data: FuzzedDataProvider) -> Self:
        pass

    def destructure(self, stream: Destructure) -> None:
        pass
