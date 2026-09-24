import os
import pwd
import socket
from pathlib import Path

import pytest

from ssh2.session import (
    LIBSSH2_METHOD_CRYPT_CS, LIBSSH2_METHOD_CRYPT_SC,
    LIBSSH2_METHOD_MAC_CS, LIBSSH2_METHOD_MAC_SC, Session,
)
from ssh2.sftp import (
    LIBSSH2_FXF_CREAT, LIBSSH2_FXF_READ, LIBSSH2_FXF_TRUNC, LIBSSH2_FXF_WRITE,
)
from .base_test import PKEY_FILENAME
from .embedded_server.openssh import OpenSSHServer


@pytest.fixture(scope="module")
def cipher_server():
    os.chmod(Path(PKEY_FILENAME).parent / "embedded_server/ca_host_key", 0o600)
    os.chmod(PKEY_FILENAME, 0o600)
    server = OpenSSHServer()
    server.start_server()
    try:
        yield
    finally:
        server.stop()


@pytest.mark.parametrize("cipher,mac", [
    ("chacha20-poly1305@openssh.com", None),
    ("aes128-gcm@openssh.com", None),
    ("aes256-gcm@openssh.com", None),
    ("aes128-ctr", "hmac-sha2-256-etm@openssh.com"),
    ("aes128-ctr", "hmac-sha2-512-etm@openssh.com"),
    ("aes256-ctr", "hmac-sha2-256"),
])
def test_encrypted_sftp_roundtrip(cipher_server, tmp_path, cipher, mac):
    payload = bytes(range(256)) * 2048
    remote_path = str(tmp_path / "payload.bin")
    sock = socket.create_connection(("127.0.0.1", 2222), timeout=3)
    session = Session()
    session.set_timeout(3000)
    sftp = None
    try:
        for method in (LIBSSH2_METHOD_CRYPT_CS, LIBSSH2_METHOD_CRYPT_SC):
            assert session.method_pref(method, cipher) == 0
        if mac is not None:
            for method in (LIBSSH2_METHOD_MAC_CS, LIBSSH2_METHOD_MAC_SC):
                assert session.method_pref(method, mac) == 0
        session.handshake(sock)
        assert session.methods(LIBSSH2_METHOD_CRYPT_CS) == cipher
        assert session.methods(LIBSSH2_METHOD_CRYPT_SC) == cipher
        if mac is not None:
            assert session.methods(LIBSSH2_METHOD_MAC_CS) == mac
            assert session.methods(LIBSSH2_METHOD_MAC_SC) == mac
        session.userauth_publickey_fromfile(
            pwd.getpwuid(os.geteuid()).pw_name, PKEY_FILENAME)
        sftp = session.sftp_init()
        with sftp.open(
            remote_path,
            LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_WRITE,
            0o600,
        ) as handle:
            handle.write(payload)
        assert Path(remote_path).read_bytes() == payload
        with sftp.open(remote_path, LIBSSH2_FXF_READ, 0o600) as handle:
            assert b"".join(data for _, data in handle) == payload
    finally:
        del sftp
        session.disconnect()
        sock.close()
