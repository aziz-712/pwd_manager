import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "server"))

import pytest

from zkvault.crypto import KdfParams

# Every test derives keys, so use the OWASP floor rather than the shipped
# defaults: the suite must be fast enough that people actually run it.
TEST_OPS = 2
TEST_MEM = 19 * 1024 * 1024


@pytest.fixture
def kdf() -> KdfParams:
    return KdfParams.generate(ops_limit=TEST_OPS, mem_limit_bytes=TEST_MEM)


@pytest.fixture
def passphrase() -> str:
    return "correct-horse-battery-staple-anvil-rope"


@pytest.fixture
def vault_path(tmp_path: Path) -> Path:
    return tmp_path / "vault.zkv"


@pytest.fixture
def zk_home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "home"
    monkeypatch.setenv("ZKVAULT_HOME", str(home))
    return home
