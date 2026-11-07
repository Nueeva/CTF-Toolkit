import hashlib
from ctf_toolkit.crypto.hashes import crack_numeric_hash


def test_crack_numeric_hash_md5() -> None:
    # 481625 -> d089f5135b655d8c0f39853d2cc2d0af
    target = hashlib.md5(b"481625").hexdigest()
    found = crack_numeric_hash(target, max_digits=6, algorithm="md5")
    assert found == "481625"


def test_crack_numeric_hash_sha256() -> None:
    # 1337 -> 4-digit PIN
    target = hashlib.sha256(b"1337").hexdigest()
    found = crack_numeric_hash(target, max_digits=4, algorithm="sha256")
    assert found == "1337"


def test_crack_numeric_hash_not_found() -> None:
    # Non-numeric hash
    target = hashlib.md5(b"non_numeric").hexdigest()
    found = crack_numeric_hash(target, max_digits=3, algorithm="md5")
    assert found is None
