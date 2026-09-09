#  This file is part of ssh2-python.
#  Copyright (C) 2017-2025 Panos Kittenis
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation, version 2.1.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public
#  License along with this library; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
"""Regression tests for the hand-ported libssh2 fix in sftp.c
(sftp_symlink(): guard SSH_FXP_NAME parsing with a bounds-checked
buffer struct -- upstream commit
2dae3024897e1898d389835151f4e9606227721d, CVE-2025-15661).

These tests run a *dedicated* local sshd whose sftp subsystem is a
tiny script (tests/fixtures/malicious_sftp_server.py) that we fully
control the wire bytes of, instead of the real internal-sftp used by
the rest of the test suite. This lets us exercise the exact malformed
SSH_FXP_NAME shape the CVE is about (a filename-length field that
lies about how much data actually follows) while the surrounding SSH
transport/auth is still a real, unmodified OpenSSH server -- no need
to reimplement SSH crypto to reach the vulnerable code path, since
sftp_symlink() only runs once a session is already authenticated.
"""
import os
import pwd
import socket
import subprocess
import sys
import unittest
from sys import version_info
from time import sleep

from ssh2.exceptions import SFTPProtocolError
from ssh2.session import Session

EMBEDDED_SERVER_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        os.pardir,
        "ci",
        "integration_tests",
        "embedded_server",
    )
)
HOST_KEY = os.path.join(EMBEDDED_SERVER_DIR, "rsa.key")
AUTHORIZED_KEYS = os.path.join(EMBEDDED_SERVER_DIR, "authorized_keys")
USER_KEY = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__), os.pardir, "ci", "integration_tests", "unit_test_key"
    )
)
FAKE_SFTP_SERVER = os.path.join(
    os.path.dirname(__file__), "fixtures", "malicious_sftp_server.py"
)

SSHD_CONFIG_BODY = """\
Protocol 2
UsePAM no
HostbasedAuthentication no
IgnoreUserKnownHosts yes
ListenAddress 127.0.0.1
HostKey {host_key}
MaxAuthTries 999
MaxSessions 999
MaxStartups 999
AcceptEnv LANG LC_*
Subsystem sftp {python} {fake_server} {mode}
AuthorizedKeysFile {authorized_keys}
PidFile {pid_file}
"""


@unittest.skipUnless(
    os.path.exists("/usr/sbin/sshd"),
    "requires a local /usr/sbin/sshd (installed by the test docker image)",
)
class SFTPSymlinkHardeningTestCase(unittest.TestCase):
    """Base class: spins up one dedicated sshd instance per subclass,
    with `Subsystem sftp` pointed at malicious_sftp_server.py running
    in `MODE`."""

    MODE = "malicious"
    PORT = 2224

    @classmethod
    def setUpClass(cls):
        _mask = int("0600") if version_info <= (2,) else 0o600
        os.chmod(HOST_KEY, _mask)

        cls.config_path = os.path.join(
            EMBEDDED_SERVER_DIR, "sshd_config_%s_test" % (cls.MODE,)
        )
        cls.pid_path = os.path.join(
            EMBEDDED_SERVER_DIR, "sshd_%s_test.pid" % (cls.MODE,)
        )
        with open(cls.config_path, "w") as fh:
            fh.write(
                SSHD_CONFIG_BODY.format(
                    host_key=HOST_KEY,
                    python=sys.executable,
                    fake_server=FAKE_SFTP_SERVER,
                    mode=cls.MODE,
                    authorized_keys=AUTHORIZED_KEYS,
                    pid_file=cls.pid_path,
                )
            )

        cls.server_proc = subprocess.Popen(
            [
                "/usr/sbin/sshd",
                "-D",
                "-p",
                str(cls.PORT),
                "-h",
                HOST_KEY,
                "-f",
                cls.config_path,
            ]
        )
        cls._wait_for_port()

    @classmethod
    def _wait_for_port(cls):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        deadline = 10
        while sock.connect_ex(("127.0.0.1", cls.PORT)) != 0:
            deadline -= 0.1
            if deadline <= 0:
                sock.close()
                raise RuntimeError("test sshd on port %s never came up" % (cls.PORT,))
            sleep(0.1)
        sock.close()

    @classmethod
    def tearDownClass(cls):
        if cls.server_proc is not None and cls.server_proc.poll() is None:
            cls.server_proc.terminate()
            cls.server_proc.wait()
        for path in (cls.config_path, cls.pid_path):
            try:
                os.unlink(path)
            except OSError:
                pass

    def setUp(self):
        self.user = pwd.getpwuid(os.geteuid()).pw_name
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(("127.0.0.1", self.PORT))
        self.sock = sock
        self.session = Session()
        self.session.handshake(sock)
        self.session.userauth_publickey_fromfile(self.user, USER_KEY)

    def tearDown(self):
        try:
            self.session.disconnect()
        except Exception:
            pass
        self.sock.close()


class MaliciousSFTPNameResponseTestCase(SFTPSymlinkHardeningTestCase):

    MODE = "malicious"
    PORT = 2224

    def test_truncated_name_length_is_rejected_not_oob_read(self):
        """A server that claims a 200-byte filename in its SSH_FXP_NAME
        reply but sends zero bytes of it must be rejected with a clean
        SFTP protocol error, not read 200 bytes past the end of the
        (13-byte) receive buffer (CVE-2025-15661)."""
        sftp = self.session.sftp_init()
        self.assertIsNotNone(sftp)
        with self.assertRaises(SFTPProtocolError):
            sftp.realpath(".")


class BenignSFTPNameResponseTestCase(SFTPSymlinkHardeningTestCase):

    MODE = "benign"
    PORT = 2225

    def test_well_formed_name_response_still_parses(self):
        """The rewritten, bounds-checked response parser must still
        accept a correctly-framed SSH_FXP_NAME reply (no regression in
        the legitimate-server path)."""
        sftp = self.session.sftp_init()
        self.assertIsNotNone(sftp)
        realpath = sftp.realpath(".")
        self.assertEqual(realpath, "/fake/realpath")


if __name__ == "__main__":
    unittest.main()
