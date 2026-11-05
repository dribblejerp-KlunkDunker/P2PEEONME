"""Additional protocol and real local-TLS regression tests.

Generated fixtures test correctness, not representative compression or speed.
GUI tests remain separate so missing Tk cannot hide backend-test results.
"""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import threading
import unittest
from unittest import mock
import zlib

import p2peeonme as app


class MemorySocket:
    def __init__(self, data=b'', fragment=7):
        self.stream = io.BytesIO(data)
        self.fragment = fragment
        self.written = bytearray()
    def recv(self, n):
        return self.stream.read(min(n, self.fragment))
    def sendall(self, data):
        self.written.extend(data)


def frame(header, payload=b''):
    raw = json.dumps(header).encode()
    return struct.pack('!I', len(raw)) + raw + payload


class ProtocolTests(unittest.TestCase):
    def test_fragmented_frame_roundtrip(self):
        sock = MemorySocket()
        app.send(sock, {'ok': True}, b'bytes\x00\xff')
        head, data = app.recv(MemorySocket(bytes(sock.written), fragment=1))
        self.assertTrue(head['ok'])
        self.assertEqual(data, b'bytes\x00\xff')

    def test_empty_payload_frame(self):
        sock = MemorySocket()
        app.send(sock, {'op': 'info'})
        self.assertEqual(app.recv(MemorySocket(bytes(sock.written)))[1], b'')

    def test_invalid_header_lengths(self):
        for n in (0, 65537, 2**32 - 1):
            with self.subTest(n=n), self.assertRaises(ValueError):
                app.recv(MemorySocket(struct.pack('!I', n)))

    def test_invalid_json_header(self):
        with self.assertRaises(ValueError):
            app.recv(MemorySocket(struct.pack('!I', 1) + b'{'))

    def test_non_object_header(self):
        for value in ([], None, 7, 'text'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                app.recv(MemorySocket(frame(value)))

    def test_invalid_payload_lengths(self):
        for n in (None, -1, True, 1.5, '4', app.LIMIT + 1):
            with self.subTest(n=n), self.assertRaises(ValueError):
                app.recv(MemorySocket(frame({'payload': n})))

    def test_connection_closes_mid_frame(self):
        for data in (b'', b'\x00', struct.pack('!I', 10) + b'{}', frame({'payload': 4}, b'ab')):
            with self.subTest(data=data), self.assertRaises(OSError):
                app.recv(MemorySocket(data))

    def test_send_rejects_oversized_frame(self):
        for header, data in (({'text': 'x' * 65536}, b''), ({}, b'x' * (app.LIMIT + 1))):
            sock = MemorySocket()
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                app.send(sock, header, data)
            self.assertEqual(sock.written, b'')

    def test_raw_decode_exact_bytes(self):
        raw = bytes(range(256))
        self.assertEqual(app.decode({'codec': 'raw', 'n': len(raw)}, raw, len(raw)), raw)

    def test_raw_decode_wrong_length(self):
        with self.assertRaises(ValueError):
            app.decode({'codec': 'raw', 'n': 4}, b'ab', 4)

    def test_unknown_codec(self):
        with self.assertRaises(ValueError):
            app.decode({'codec': 'unknown', 'n': 2}, b'ab', 2)

    def test_compressed_roundtrip(self):
        raw = b'functional fixture' * 100
        self.assertEqual(app.decode({'codec': 'zlib', 'n': len(raw)}, zlib.compress(raw), len(raw)), raw)

    def test_trailing_or_concatenated_compressed_data(self):
        packed = zlib.compress(b'abcd')
        for data in (packed + b'junk', packed + packed):
            with self.subTest(data=data), self.assertRaises(ValueError):
                app.decode({'codec': 'zlib', 'n': 4}, data, 4)

    def test_truncated_compressed_data(self):
        with self.assertRaises(ValueError):
            app.decode({'codec': 'zlib', 'n': 4}, zlib.compress(b'abcd')[:-1], 4)

    def test_declared_size_mismatch(self):
        with self.assertRaises(ValueError):
            app.decode({'codec': 'raw', 'n': 5}, b'abcd', 4)

    def test_valid_relative_names(self):
        for name in ('folder/file.unknown', 'caf\u00e9.txt', 'a b/data.bin', 'file'):
            with self.subTest(name=name):
                self.assertEqual(str(app.relative(name)), name)

    def test_nonportable_and_traversal_names(self):
        for name in ('', '../x', '/x', 'a//b', 'a/./b', 'a/../b', 'a\\b', 'a\x00b',
                     'NUL.txt', 'COM1.log', 'LPT9', 'trail.', 'trail ', 'a:stream'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                app.relative(name)

    def test_invalid_invitation_envelope(self):
        for code in ('', 'wrong.prefix', 'pee1.' + 'a' * 4097,
                     'pee1.' + base64.urlsafe_b64encode(b'[]').decode()):
            with self.subTest(code=code[:20]), self.assertRaises(ValueError):
                app.Client(code)

    def test_worker_limits_before_connect(self):
        for count in (0, -1, 9):
            with self.subTest(count=count), mock.patch.object(app, 'Client') as client:
                with self.assertRaises(ValueError):
                    app.download('not used', '.', workers=count)
                client.assert_not_called()


class TransferRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.home = mock.patch.object(Path, 'home', return_value=self.root / 'home')
        self.home.start()
    def tearDown(self):
        self.home.stop()
        self.temporary.cleanup()
    def write(self, name, data):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path
    @contextlib.contextmanager
    def serving(self, source=None):
        share = app.Share(source if source is not None else self.source,
                          '127.0.0.1', 0, '127.0.0.1', lambda s: None)
        try:
            yield share
        finally:
            share.stop()
    def receive(self, share, **kwargs):
        return app.download(share.invitation, self.root / 'out', log=lambda s: None, **kwargs)

    def test_empty_folder(self):
        with self.serving() as share:
            stats = self.receive(share)
            self.assertTrue(Path(stats['output']).is_dir())
            self.assertEqual(stats['payload_bytes'], 0)

    def test_single_file_chunk_boundaries(self):
        for size in (0, 1, app.CHUNK - 1, app.CHUNK, app.CHUNK + 1):
            with self.subTest(size=size):
                path = self.write('boundary.bin', b'q' * size)
                with self.serving(path) as share:
                    stats = self.receive(share, workers=2)
                    self.assertEqual((Path(stats['output']) / path.name).read_bytes(), path.read_bytes())

    def test_nested_unicode_unknown_extension(self):
        path = self.write('nested/caf\u00e9.unknown', bytes(range(256)) * 17)
        with self.serving() as share:
            stats = self.receive(share)
            self.assertEqual((Path(stats['output']) / path.relative_to(self.source)).read_bytes(), path.read_bytes())

    def test_wrong_certificate_pin(self):
        self.write('data', b'hello')
        with self.serving() as share:
            client = app.Client(share.invitation)
            client.inv['pin'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'pin mismatch'):
                client.request('info')

    def test_wrong_token_rejected(self):
        self.write('data', b'hello')
        with self.serving() as share:
            client = app.Client(share.invitation)
            client.inv['token'] = 'wrong-token'
            with self.assertRaises(OSError):
                client.request('info')

    def test_source_change_rejected(self):
        path = self.write('data', b'hello')
        with self.serving() as share:
            path.write_bytes(b'a different length')
            with self.assertRaises(OSError):
                self.receive(share)
            self.assertFalse(list((self.root / 'out').glob('P2PEEONME-*/data')))

    def test_existing_different_output_not_overwritten(self):
        self.write('data', b'original')
        with self.serving() as share:
            stats = self.receive(share)
            target = Path(stats['output']) / 'data'
            target.write_bytes(b'keep this')
            with self.assertRaisesRegex(ValueError, 'overwrite'):
                self.receive(share)
            self.assertEqual(target.read_bytes(), b'keep this')

    def test_corrupt_partial_chunk_redownloaded(self):
        raw = os.urandom(app.CHUNK * 3 + 13)
        self.write('data', raw)
        stop = threading.Event()
        def progress(message):
            if 'chunks verified' in message:
                stop.set()
        with self.serving() as share:
            with self.assertRaises(ValueError):
                app.download(share.invitation, self.root / 'out', 1, progress, stop)
            part = next((self.root / 'out').glob('P2PEEONME-*/.p2peeonme-partials/0.part'))
            with part.open('r+b') as handle:
                handle.write(b'corrupted')
            stats = self.receive(share, workers=1)
            self.assertEqual((Path(stats['output']) / 'data').read_bytes(), raw)
            self.assertGreaterEqual(stats['downloaded_original_bytes'], app.CHUNK)

    def test_pre_cancelled_transfer_does_not_publish(self):
        self.write('data', b'hello')
        stop = threading.Event()
        stop.set()
        with self.serving() as share:
            with self.assertRaisesRegex(ValueError, 'Paused'):
                self.receive(share, stop=stop)
            self.assertFalse(list((self.root / 'out').glob('P2PEEONME-*/data')))

    def test_checksum_failure_does_not_publish(self):
        self.write('data', b'original bytes')
        with self.serving() as share:
            with mock.patch.object(app, 'decode', side_effect=lambda h, p, n: b'!' * n):
                with self.assertRaisesRegex(ValueError, 'checksum'):
                    self.receive(share)
            self.assertFalse(list((self.root / 'out').glob('P2PEEONME-*/data')))


if __name__ == '__main__':
    unittest.main(verbosity=2)
