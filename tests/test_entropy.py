import os
import sys
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from edr import EntropyEngine


def test_low_entropy():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"A" * 1000)
        fp = f.name
    e = EntropyEngine.file_entropy(fp)
    os.unlink(fp)
    assert e < 1.0


def test_high_entropy():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(os.urandom(1000))
        fp = f.name
    e = EntropyEngine.file_entropy(fp)
    os.unlink(fp)
    assert e > 7.0


def test_empty_file():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        fp = f.name
    e = EntropyEngine.file_entropy(fp)
    os.unlink(fp)
    assert e == 0.0
