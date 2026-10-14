from quiver.api.auth import hash_password, hash_token, verify_password


def test_password_roundtrip():
    h = hash_password("correct horse battery staple")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "correct horse battery staple")
    assert not verify_password(h, "wrong password")


def test_invalid_hash_does_not_raise():
    assert not verify_password("not-a-hash", "anything")


def test_token_hash_is_keyed():
    assert hash_token("tok", "key-a") == hash_token("tok", "key-a")
    assert hash_token("tok", "key-a") != hash_token("tok", "key-b")
    assert "tok" not in hash_token("tok", "key-a")
