#!/usr/bin/env python3
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
"""Minimal, deliberately malicious SFTP subsystem used ONLY by
tests/test_sftp_symlink_hardening.py.

It is installed as the sshd `Subsystem sftp` command for a *dedicated*
test sshd instance (a second port, separate from the normal embedded
test server), so it never affects any other test. It speaks just
enough of the SFTP wire protocol to complete SSH_FXP_INIT/VERSION and
then answers any REALPATH/READLINK/SYMLINK request with a corrupted
SSH_FXP_NAME response that *lies* about the length of the returned
filename: it declares a name string of 200 bytes while sending zero
bytes of actual name data.

This exact shape is what CVE-2025-15661 is about: libssh2's
`sftp_symlink()` used to trust that on-the-wire length unconditionally
and `memcpy()` that many bytes out of its (much shorter) receive
buffer -- a heap out-of-bounds read/information disclosure. The fixed
`sftp_symlink()` parses the response through `struct string_buf` /
`_libssh2_get_string()`, which bounds-checks the claimed length against
the bytes actually received and fails cleanly instead.
"""
import struct
import sys

SSH_FXP_INIT = 1
SSH_FXP_VERSION = 2
SSH_FXP_NAME = 104


def read_exact(n):
    buf = b""
    while len(buf) < n:
        chunk = sys.stdin.buffer.read(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


def read_packet():
    hdr = read_exact(4)
    if len(hdr) < 4:
        return None
    (length,) = struct.unpack(">I", hdr)
    return read_exact(length)


def write_packet(payload):
    sys.stdout.buffer.write(struct.pack(">I", len(payload)) + payload)
    sys.stdout.buffer.flush()


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "malicious"

    init_pkt = read_packet()
    if init_pkt is None or not init_pkt or init_pkt[0] != SSH_FXP_INIT:
        return 1

    # SSH_FXP_VERSION: byte type; uint32 version (no extensions).
    write_packet(struct.pack(">BI", SSH_FXP_VERSION, 3))

    request = read_packet()
    if request is None or len(request) < 5:
        return 0

    request_id = struct.unpack(">I", request[1:5])[0]

    if mode == "benign":
        # A correctly-formed SSH_FXP_NAME response with a single,
        # accurately-length-prefixed entry -- proves the rewritten
        # response parser still accepts legitimate replies.
        name = b"/fake/realpath"
        longname = name
        attrs = struct.pack(">I", 0)  # empty ATTRS (no flags set)
        payload = (
            struct.pack(">BII", SSH_FXP_NAME, request_id, 1)
            + struct.pack(">I", len(name))
            + name
            + struct.pack(">I", len(longname))
            + longname
            + attrs
        )
        write_packet(payload)
        return 0

    # Malicious SSH_FXP_NAME response:
    #   byte    type = SSH_FXP_NAME
    #   uint32  request-id
    #   uint32  count = 1
    #   uint32  filename length = 200   <-- lie: no bytes follow
    # (no filename bytes, no longname, no attrs)
    malicious_payload = struct.pack(">BIII", SSH_FXP_NAME, request_id, 1, 200)
    write_packet(malicious_payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
