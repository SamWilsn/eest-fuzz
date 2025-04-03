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

from dataclasses import dataclass, field


@dataclass
class Destructure:
    head: bytearray = field(default_factory=bytearray)
    tail: bytearray = field(default_factory=bytearray)

    def write_head(self, data: bytes):
        self.head.extend(data)

    def write_tail(self, data: bytes):
        self.tail.extend(reversed(data))

    def build(self):
        return bytes(self.head + bytes(reversed(self.tail)))
