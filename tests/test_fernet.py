import base64
from ctf_toolkit.crypto.fernet import fernet_decrypt


def test_fernet_decrypt():
    # Known key and test token
    # Fernet key: 32 URL-safe base64-encoded bytes
    key = b"lyAdYdy61IarehpSmjO-l9UflJ8-lZdCkdIAN3hA7FM="
    token = b"gAAAAABq6t-_nCCXWOhD7tBYTUR-XK7nNxh4R_Brmmd8l7q6SDN4EU7-h38rkHZDx39IqvSzDedhmVjg-jhxA0COc5n6_2ruucWdR81TAbSi6Rv5CXZj5WA="
    decrypted = fernet_decrypt(token, key)
    assert decrypted == b"GETSFLAG{fernet_token_decrypt}"
