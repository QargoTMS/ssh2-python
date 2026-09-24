import os
import socket
import tempfile
import time
from pathlib import Path

from ssh2.error_codes import LIBSSH2_ERROR_EAGAIN
from ssh2.exceptions import BufferTooSmallError, SFTPProtocolError
from ssh2.session import Session
from ssh2.utils import wait_socket

from .base_test import SSH2TestCase
from .embedded_server.tcp_reply_gate import TCPReplyGate


class SFTPStatusRegressionTestCase(SSH2TestCase):

    def setUp(self):
        super().setUp()
        self._auth()
        self.session.set_timeout(3000)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def _sftp_at_request(self, request_id):
        sftp = self.session.sftp_init()
        # Advance the real request counter using ordinary successful requests.
        for _ in range(request_id):
            self.assertEqual(
                sftp.realpath(self.directory.name), self.directory.name)
        return sftp

    def _missing(self, request_id):
        sftp = self._sftp_at_request(request_id)
        with self.assertRaises(SFTPProtocolError):
            sftp.realpath(self.directory.name + "/missing/child")
        self.assertEqual(sftp.last_error(), 2)

    def test_missing_realpath_id_zero(self):
        self._missing(0)

    def test_missing_realpath_id_one(self):
        self._missing(1)

    def _symlink(self, request_id):
        sftp = self._sftp_at_request(request_id)
        link = self.directory.name + "/link"
        error = None
        result = None
        try:
            result = sftp.symlink("target", link)
        except SFTPProtocolError as exc:
            error = exc
        self.assertTrue(
            os.path.islink(link), "server must actually create the symlink")
        self.assertEqual(os.readlink(link), "target")
        self.assertIsNone(
            error, "successful remote write reported as failure: %r, status=%s"
            % (error, sftp.last_error()))
        self.assertEqual(result, 0)
        self.assertEqual(sftp.last_error(), 0)

    def test_successful_symlink_id_zero(self):
        self._symlink(0)

    def test_successful_symlink_id_one(self):
        self._symlink(1)

    def test_existing_destination_symlink_id_zero(self):
        sftp = self._sftp_at_request(0)
        link = self.directory.name + "/existing"
        with open(link, "w") as output:
            output.write("keep")
        with self.assertRaises(SFTPProtocolError):
            sftp.symlink("target", link)
        self.assertEqual(sftp.last_error(), 4)
        with open(link) as source:
            self.assertEqual(source.read(), "keep")

    def test_realpath_output_buffer_boundary_and_recovery(self):
        sftp = self._sftp_at_request(0)
        path = Path(self.directory.name)
        for _ in range(4):
            path /= "é" * 40
        path.mkdir(parents=True)
        path = str(path)
        size = len(os.fsencode(path))
        self.assertGreater(size, 256)
        with self.assertRaises(BufferTooSmallError):
            sftp.realpath(path)
        with self.assertRaises(BufferTooSmallError):
            sftp.realpath(path, max_len=size)
        # NAME replies need room for encoded bytes and the NUL terminator.
        self.assertEqual(sftp.realpath(path, max_len=size + 1), path)

    def test_error_then_success_clears_status(self):
        sftp = self._sftp_at_request(0)
        with self.assertRaises(SFTPProtocolError):
            sftp.realpath(self.directory.name + "/missing/child")
        self.assertEqual(sftp.last_error(), 2)
        link = self.directory.name + "/recovered-link"
        self.assertEqual(sftp.symlink("target", link), 0)
        self.assertEqual(os.readlink(link), "target")
        self.assertEqual(sftp.last_error(), 0)
        self.assertEqual(
            sftp.realpath(self.directory.name), self.directory.name)

    def test_nonblocking_name_status_and_recovery(self):
        # Reconnect through a gate that pauses delivery of unchanged replies
        # from the fixture's normal OpenSSH server.
        self.session.disconnect()
        self.sock.close()
        gate = TCPReplyGate(self.host, self.port)
        self.addCleanup(gate.stop)
        self.sock = socket.create_connection((self.host, gate.port), timeout=3)
        self.session = Session()
        self.session.set_timeout(3000)
        self.session.handshake(self.sock)
        self._auth()
        sftp = self.session.sftp_init()
        self.session.set_blocking(False)

        def complete_after_wait(operation, *args):
            gate.pause()
            try:
                self.assertEqual(operation(*args), LIBSSH2_ERROR_EAGAIN)
            finally:
                gate.resume()
            deadline = time.monotonic() + 5
            while True:
                result = operation(*args)
                if result != LIBSSH2_ERROR_EAGAIN:
                    return result
                self.assertLess(time.monotonic(), deadline,
                                "operation did not resume")
                wait_socket(self.sock, self.session, timeout=0.1)

        try:
            path = self.directory.name
            self.assertEqual(complete_after_wait(sftp.realpath, path), path)
            link = path + "/link"
            self.assertEqual(
                complete_after_wait(sftp.symlink, "target", link), 0)
            self.assertEqual(os.readlink(link), "target")
            with self.assertRaises(SFTPProtocolError):
                complete_after_wait(sftp.realpath, path + "/missing/child")
            self.assertEqual(sftp.last_error(), 2)
            self.assertEqual(complete_after_wait(sftp.realpath, path), path)
            self.assertEqual(sftp.last_error(), 0)
        finally:
            gate.resume()
            self.session.set_blocking(True)
