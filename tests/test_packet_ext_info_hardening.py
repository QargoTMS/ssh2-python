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
"""Regression test for the hand-ported libssh2 fix in packet.c
(check _libssh2_get_string() return value in the SSH_MSG_EXT_INFO
loop and break on failure -- upstream commit
17626857d20b3c9a1addfa45979dadcee1cd84a4, CVE-2026-55199).

`_libssh2_packet_add()` is an internal libssh2 function that parses
one already-received, already-decrypted SSH packet: it only needs a
valid LIBSSH2_SESSION* (no socket, no completed key exchange) to run.
It isn't part of libssh2's public API though, so the vendored shared
library (ssh2/libssh2.so*, built with -fvisibility=hidden per
libssh2/CMakeLists.txt's HIDE_SYMBOLS option) does not export it for
ctypes to call.

Instead we compile a tiny, throwaway C harness at test time and link
it directly against the vendored *static* archive
(build_dir/src/libssh2.a, produced by the same
'python setup.py build_ext --inplace' step that builds the shared
library) -- that archive still contains internal symbols with normal
linkage, since HIDE_SYMBOLS only applies -fvisibility=hidden to the
shared-library build. The harness calls _libssh2_packet_add() with a
hand-crafted, truncated SSH_MSG_EXT_INFO payload -- exactly the
"nr-extensions says N, buffer contains fewer than N pairs" shape the
CVE is about -- and reports back via its exit code. If the fix
regressed and this really did read/write out of bounds, the harness
process crashes (non-zero / signal exit code) and fails the test
instead of taking down the whole test run.
"""
import os
import struct
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
LIBSSH2_SRC_DIR = os.path.join(REPO_ROOT, "libssh2", "src")
LIBSSH2_INCLUDE_DIR = os.path.join(REPO_ROOT, "libssh2", "include")
BUILD_DIR_SRC = os.path.join(REPO_ROOT, "build_dir", "src")
STATIC_LIB = os.path.join(BUILD_DIR_SRC, "libssh2.a")

SSH_MSG_EXT_INFO = 7
LIBSSH2_MAC_CONFIRMED = 0

HARNESS_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libssh2_priv.h"
#include "packet.h"

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "usage: %s <hex-payload>\n", argv[0]);
        return 3;
    }

    LIBSSH2_SESSION *session = libssh2_session_init();
    if(!session) {
        fprintf(stderr, "libssh2_session_init() returned NULL\n");
        return 3;
    }

    const char *hex = argv[1];
    size_t hexlen = strlen(hex);
    size_t datalen = hexlen / 2;
    unsigned char *data = malloc(datalen ? datalen : 1);
    if(!data) {
        fprintf(stderr, "malloc failed\n");
        return 3;
    }
    for(size_t i = 0; i < datalen; i++) {
        unsigned int byte;
        sscanf(hex + i * 2, "%2x", &byte);
        data[i] = (unsigned char)byte;
    }

    int rc = _libssh2_packet_add(session, data, datalen,
                                 LIBSSH2_MAC_CONFIRMED, 0);
    printf("%d\n", rc);
    fflush(stdout);
    return rc == 0 ? 0 : 2;
}
"""


def _build_harness(tmpdir):
    src_path = os.path.join(tmpdir, "harness.c")
    bin_path = os.path.join(tmpdir, "harness")
    with open(src_path, "w") as fh:
        fh.write(HARNESS_SOURCE)

    compile_cmd = [
        "cc",
        "-DHAVE_CONFIG_H",
        "-DLIBSSH2_OPENSSL",
        "-I",
        LIBSSH2_SRC_DIR,
        "-I",
        LIBSSH2_INCLUDE_DIR,
        "-I",
        BUILD_DIR_SRC,
        src_path,
        STATIC_LIB,
        "-lssl",
        "-lcrypto",
        "-lz",
        "-lpthread",
        "-ldl",
        "-o",
        bin_path,
    ]
    proc = subprocess.run(compile_cmd, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(
            "failed to compile EXT_INFO hardening test harness: %s\n%s"
            % (
                proc.stdout.decode(errors="replace"),
                proc.stderr.decode(errors="replace"),
            )
        )
    return bin_path


@unittest.skipUnless(
    os.path.exists(STATIC_LIB),
    "requires the vendored libssh2 static archive built by "
    "'python setup.py build_ext --inplace' (build_dir/src/libssh2.a)",
)
class ExtInfoHardeningTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._tmpdir = tempfile.mkdtemp(prefix="ssh2_ext_info_test_")
        cls.harness = _build_harness(cls._tmpdir)

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls._tmpdir, ignore_errors=True)

    def _run_packet_add(self, payload):
        return subprocess.run(
            [self.harness, payload.hex()], capture_output=True, timeout=15
        )

    def test_truncated_ext_info_does_not_crash_and_breaks_cleanly(self):
        """nr-extensions claims 2 pairs follow; the buffer ends right
        after that count with zero bytes of actual name/value data."""
        payload = struct.pack(">BI", SSH_MSG_EXT_INFO, 2)
        proc = self._run_packet_add(payload)
        self.assertEqual(
            proc.returncode,
            0,
            "harness crashed or _libssh2_packet_add() returned an "
            "error for a merely-truncated EXT_INFO packet: rc=%r "
            "stdout=%r stderr=%r" % (proc.returncode, proc.stdout, proc.stderr),
        )

    def test_truncated_value_after_valid_name_does_not_crash(self):
        """The name string parses fine, but the value string's length
        prefix claims more bytes than actually remain."""
        name = b"server-sig-algs"
        payload = (
            struct.pack(">BI", SSH_MSG_EXT_INFO, 1)
            + struct.pack(">I", len(name))
            + name
            + struct.pack(">I", 5000)  # value length lies, no bytes follow
        )
        proc = self._run_packet_add(payload)
        self.assertEqual(
            proc.returncode,
            0,
            "harness crashed or _libssh2_packet_add() returned an "
            "error for a truncated EXT_INFO value string: rc=%r "
            "stdout=%r stderr=%r" % (proc.returncode, proc.stdout, proc.stderr),
        )

    def test_well_formed_ext_info_still_parses(self):
        """A single, correctly-framed extension pair must still be
        accepted (no regression in the legitimate-server path)."""
        name = b"server-sig-algs"
        value = b"ssh-ed25519"
        payload = (
            struct.pack(">BI", SSH_MSG_EXT_INFO, 1)
            + struct.pack(">I", len(name))
            + name
            + struct.pack(">I", len(value))
            + value
        )
        proc = self._run_packet_add(payload)
        self.assertEqual(
            proc.returncode,
            0,
            "well-formed EXT_INFO packet was rejected: rc=%r stdout=%r "
            "stderr=%r" % (proc.returncode, proc.stdout, proc.stderr),
        )


if __name__ == "__main__":
    unittest.main()
