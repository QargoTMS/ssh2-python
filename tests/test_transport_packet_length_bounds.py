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
"""Regression test for the hand-ported libssh2 fix in transport.c
(bound packet_length before use in _libssh2_transport_read -- upstream
commit 97acf3dfda80c91c3a8c9f2372546301d4a1a7a8, CVE-2026-55200).

A fake, unauthenticated TCP peer completes only the plaintext SSH
version-banner exchange and then sends a single raw binary packet
whose declared packet_length is far larger than
LIBSSH2_PACKET_MAXPAYLOAD (40000). No key exchange/crypto is needed to
reach this: the very first binary packet after the banner exchange
(normally KEXINIT) is read by the same `_libssh2_transport_read()`
this bug is in, before any cipher is negotiated. The client must
reject it cleanly instead of sizing an allocation/read from the
unbounded value.
"""
import socket
import struct
import threading
import unittest

from ssh2.exceptions import SSH2Error
from ssh2.session import Session

# Comfortably larger than LIBSSH2_PACKET_MAXPAYLOAD (40000).
OVERSIZED_PACKET_LENGTH = 0xFFFFFFF0


class TransportPacketLengthBoundsTestCase(unittest.TestCase):

    def _fake_peer(self, listener, exc_box):
        try:
            conn, _ = listener.accept()
            try:
                conn.settimeout(10)
                conn.sendall(b"SSH-2.0-libssh2_test_malicious\r\n")
                # Drain whatever banner the client sent us; not required
                # for the bug, just keeps the exchange tidy.
                try:
                    conn.recv(256)
                except socket.timeout:
                    pass
                # A single raw (pre-encryption) SSH binary packet: 4-byte
                # packet_length + 1-byte padding_length. packet_length is
                # deliberately way past LIBSSH2_PACKET_MAXPAYLOAD.
                conn.sendall(struct.pack(">IB", OVERSIZED_PACKET_LENGTH, 4))
            finally:
                conn.close()
        except Exception as exc:  # pragma: no cover - diagnostic only
            exc_box.append(exc)

    def test_oversized_packet_length_rejected(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        exc_box = []
        server_thread = threading.Thread(
            target=self._fake_peer, args=(listener, exc_box)
        )
        server_thread.daemon = True
        server_thread.start()

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # OS-level receive/send timeouts so a regression that makes the
        # client block forever fails the test instead of hanging the
        # whole run -- these apply to the raw fd libssh2 reads/writes
        # directly, unlike socket.settimeout()'s Python-level emulation.
        client_sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 10, 0)
        )
        client_sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_SNDTIMEO, struct.pack("ll", 10, 0)
        )

        try:
            client_sock.connect(("127.0.0.1", port))
            session = Session()
            with self.assertRaises(SSH2Error):
                session.handshake(client_sock)
        finally:
            server_thread.join(timeout=15)
            listener.close()
            client_sock.close()

        self.assertEqual(exc_box, [])


if __name__ == "__main__":
    unittest.main()
