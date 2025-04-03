from eest_fuzz.destructure import Destructure


def test_build():
    d = Destructure()
    d.write_head(b"abcd")
    d.write_tail(b"efgh")
    assert d.build() == b"abcdefgh"
