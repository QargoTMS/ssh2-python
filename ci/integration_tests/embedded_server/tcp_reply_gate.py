"""Pause reply delivery from a real server without changing protocol bytes."""

import multiprocessing
import select
import socket


def _forward(listener, upstream, ready, stopped):
    with listener:
        client, _ = listener.accept()
        with client, socket.create_connection(upstream, timeout=3) as server:
            while not stopped.is_set():
                inputs = [client, server] if ready.is_set() else [client]
                readable, _, _ = select.select(inputs, [], [], 0.02)
                for source in readable:
                    if source is server and not ready.is_set():
                        continue
                    data = source.recv(65536)
                    if not data:
                        return
                    (server if source is client else client).sendall(data)


class TCPReplyGate:
    """Forward in a separate process so native client calls cannot stall it."""

    def __init__(self, host, port):
        context = multiprocessing.get_context("fork")
        self._ready = context.Event()
        self._stopped = context.Event()
        self._ready.set()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            self.port = listener.getsockname()[1]
            self._process = context.Process(
                target=_forward,
                args=(listener, (host, port), self._ready, self._stopped),
            )
            self._process.start()

    def pause(self):
        self._ready.clear()

    def resume(self):
        self._ready.set()

    def stop(self):
        self.resume()
        self._stopped.set()
        self._process.join(timeout=2)
        if self._process.is_alive():
            self._process.terminate()
            self._process.join(timeout=2)
