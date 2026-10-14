import importlib.util
import stat
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "init_secrets", Path(__file__).parent.parent / "scripts" / "init_secrets.py"
)
init_secrets_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(init_secrets_mod)
init_secrets = init_secrets_mod.init_secrets


def test_creates_all_secrets(tmp_path):
    results = init_secrets(tmp_path)
    assert set(results) == set(init_secrets_mod.SECRETS)
    assert all(status == "created" for status in results.values())
    for name in results:
        value = (tmp_path / "secrets" / name).read_text()
        assert len(value) >= 32


def test_secret_dir_is_private(tmp_path):
    init_secrets(tmp_path)
    mode = stat.S_IMODE((tmp_path / "secrets").stat().st_mode)
    assert mode == 0o700


def test_rerun_never_overwrites(tmp_path):
    init_secrets(tmp_path)
    before = {p.name: p.read_text() for p in (tmp_path / "secrets").iterdir()}
    results = init_secrets(tmp_path)
    assert all(status == "kept" for status in results.values())
    after = {p.name: p.read_text() for p in (tmp_path / "secrets").iterdir()}
    assert before == after


def test_empty_file_is_regenerated(tmp_path):
    init_secrets(tmp_path)
    (tmp_path / "secrets" / "postgres_password").write_text("")
    results = init_secrets(tmp_path)
    assert results["postgres_password"] == "created"
    assert (tmp_path / "secrets" / "postgres_password").read_text()


def test_values_are_unique(tmp_path):
    init_secrets(tmp_path)
    values = [p.read_text() for p in (tmp_path / "secrets").iterdir()]
    assert len(values) == len(set(values))
