import tempfile, unittest, os, threading
from pathlib import Path
import p2peeonme as app

class TransferTests(unittest.TestCase):
    def test_paths(self):
        for p in ['../x', '/x', 'a/../b', 'a\\b', 'CON', 'a:stream']:
            with self.subTest(p=p), self.assertRaises(ValueError):
                app.relative(p)
    def test_decode_bounds(self):
        import zlib
        with self.assertRaises(ValueError):
            app.decode({'codec': 'zlib', 'n': 10}, zlib.compress(b'x' * 10000), 10)
    def test_roundtrip_and_rerun(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            src = t / 'source'
            src.mkdir()
            for name, data in [('empty', b''), ('random.unknown', os.urandom(1100000)), ('repeat.txt', b'hello' * 230000)]:
                (src / name).write_bytes(data)
            share = app.Share(src, '127.0.0.1', 0, '127.0.0.1', lambda s: None)
            try:
                stats = app.download(share.invitation, t / 'out', 2, lambda s: None)
                out = Path(stats['output'])
                for p in src.iterdir():
                    self.assertEqual(p.read_bytes(), (out / p.name).read_bytes())
                second = app.download(share.invitation, t / 'out', 1, lambda s: None)
                self.assertEqual(second['payload_bytes'], 0)
            finally:
                share.stop()
    def test_interruption_resume(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            src = t / 'source'
            src.mkdir()
            (src / 'large').write_bytes(os.urandom(app.CHUNK * 5 + 27))
            share = app.Share(src, '127.0.0.1', 0, '127.0.0.1', lambda s: None)
            stop = threading.Event()
            try:
                def log(s):
                    if 'chunks verified' in s:
                        stop.set()
                with self.assertRaises(ValueError):
                    app.download(share.invitation, t / 'out', 1, log, stop)
                stats = app.download(share.invitation, t / 'out', 1, lambda s: None)
                self.assertEqual((Path(stats['output']) / 'large').read_bytes(), (src / 'large').read_bytes())
                self.assertLess(stats['payload_bytes'], (src / 'large').stat().st_size)
            finally:
                share.stop()

if __name__ == '__main__':
    unittest.main(verbosity=2)
