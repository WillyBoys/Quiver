import pytest

from quiver.core.config import SecretFileError, Settings


def test_db_url_reads_password_from_file(tmp_path):
    pw = tmp_path / "pw"
    pw.write_text("s3cret-value\n")
    url = Settings(db_host="db", db_password_file=pw).db_url()
    assert url.password == "s3cret-value"
    assert url.host == "db"
    assert url.drivername == "postgresql+asyncpg"


def test_missing_password_file_is_an_error(tmp_path):
    with pytest.raises(SecretFileError, match="cannot read"):
        Settings(db_password_file=tmp_path / "nope").db_url()


def test_unconfigured_secret_is_an_error():
    with pytest.raises(SecretFileError, match="not configured"):
        Settings().secret_key()


def test_empty_secret_file_is_an_error(tmp_path):
    empty = tmp_path / "empty"
    empty.write_text("  \n")
    with pytest.raises(SecretFileError, match="empty"):
        Settings(secret_key_file=empty).secret_key()


def test_database_url_override():
    url = "postgresql+asyncpg://u:p@h:1/d"
    assert Settings(database_url=url).db_url() == url


def test_secrets_are_not_in_repr(tmp_path):
    s = Settings(database_url="postgresql+asyncpg://u:hunter2-pw@h/d")
    assert "hunter2-pw" not in repr(s)
