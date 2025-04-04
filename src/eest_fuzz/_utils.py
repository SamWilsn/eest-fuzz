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

from struct import pack
from .destructure import Destructure


def unpick_value_in_list(index: int, count: int, output: Destructure) -> None:
    if count < 2**8:
        output.write_tail(pack("<B", index))
    elif count < 2**16:
        output.write_tail(pack("<H", index))
    elif count < 2**32:
        output.write_tail(pack("<I", index))
    elif count < 2**64:
        output.write_tail(pack("<Q", index))
    else:
        raise ValueError("too many items in list")
