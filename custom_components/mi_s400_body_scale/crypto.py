from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass(frozen=True)
class SessionKeys:
    dev_key: bytes
    app_key: bytes
    dev_iv: bytes
    app_iv: bytes


def derive_login_keys(token: bytes, app_rand: bytes, dev_rand: bytes) -> SessionKeys:
    salt = app_rand + dev_rand
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b"mible-login-info",
        backend=default_backend(),
    ).derive(token)
    return SessionKeys(
        dev_key=derived[0:16],
        app_key=derived[16:32],
        dev_iv=derived[32:36],
        app_iv=derived[36:40],
    )


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def decrypt_cmtp(keys: SessionKeys, raw: bytes) -> bytes | None:
    if len(raw) < 6:
        return None
    try:
        it = raw[:2]
        ct = raw[2:]
        nonce = keys.dev_iv + bytes(4) + it + bytes(2)
        return AESCCM(keys.dev_key, tag_length=4).decrypt(nonce, ct, None)
    except Exception:
        return None
