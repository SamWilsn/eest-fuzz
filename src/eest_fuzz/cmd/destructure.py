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

from eest_fuzz import destructure, Destructure, structure
import sys
import json
from ethereum_test_fixtures.state import StateFixture
from os import walk, makedirs
from os.path import join
from pathlib import Path
import atheris
from hashlib import sha1

def main():
    outdir = sys.argv[2]
    makedirs(outdir, exist_ok=True)

    count = 0
    for dirname, _, filenames in walk(sys.argv[1]):
        for filename in filenames:
            if not filename.endswith(".json"):
                continue

            path = join(dirname, filename)
            relpath = path.removeprefix(sys.argv[1])

            with open(path, "r") as f:
                contents = json.load(f)

            for index, value in enumerate(contents.values()):
                model = StateFixture.model_validate(value)
                model.info = {}
                de = Destructure()
                destructure(StateFixture, model, de)
                buf = de.build()

                st = structure(StateFixture, atheris.FuzzedDataProvider(buf))

                if model != st:
                    print(model)
                    print(st)
                    raise Exception

                outpath = join(outdir, sha1(buf).hexdigest())
                with open(outpath, "wb") as f:
                    f.write(buf)


if __name__ == "__main__":
    main()
