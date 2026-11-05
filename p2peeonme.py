"""P2PEEONME experimental direct TLS transfer. Python 3.10+."""
import argparse, base64, concurrent.futures, datetime, hashlib, json, os
from pathlib import Path, PurePosixPath
import queue, secrets, socket, socketserver, ssl, struct, threading, time, zlib

CHUNK = 1024 * 1024
LIMIT = CHUNK + 65536

def sha(data):
    return hashlib.sha256(data).hexdigest()

def filehash(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while b := f.read(CHUNK):
            h.update(b)
    return h.hexdigest()

def exact(sock, n):
    out = bytearray()
    while len(out) < n:
        b = sock.recv(min(65536, n - len(out)))
        if not b:
            raise OSError('Connection closed')
        out.extend(b)
    return bytes(out)

def send(sock, obj, data=b''):
    h = json.dumps(dict(obj, payload=len(data)), separators=(',', ':')).encode()
    if len(h) > 65536 or len(data) > LIMIT:
        raise ValueError('Oversized frame')
    sock.sendall(struct.pack('!I', len(h)) + h + data)

def recv(sock):
    n = struct.unpack('!I', exact(sock, 4))[0]
    if not 0 < n <= 65536:
        raise ValueError('Invalid frame header')
    h = json.loads(exact(sock, n))
    if not isinstance(h, dict):
        raise ValueError('Invalid message')
    n = h.get('payload')
    if type(n) is not int or not 0 <= n <= LIMIT:
        raise ValueError('Invalid frame payload')
    return h, exact(sock, n)

def relative(name):
    if not isinstance(name, str) or not name or '\\' in name or '\x00' in name:
        raise ValueError('Unsafe path')
    p = PurePosixPath(name)
    if p.is_absolute() or any(s in ('', '.', '..') for s in name.split('/')):
        raise ValueError('Unsafe path')
    reserved = {'CON', 'PRN', 'AUX', 'NUL'} | {f'{x}{i}' for x in ('COM', 'LPT') for i in range(1, 10)}
    for s in p.parts:
        if any(c in s for c in '<>:"|?*') or s.endswith((' ', '.')) or s.split('.')[0].upper() in reserved:
            raise ValueError('Nonportable filename')
    return p

def private_path(p):
    p = Path(p).absolute()
    if any(x.is_symlink() for x in (p, *p.parents)):
        raise ValueError('Symlinks not supported')
    return p

def certificate(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'P2PEEONME experimental share')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    directory.mkdir(parents=True, exist_ok=True)
    cp, kp = directory / 'cert.pem', directory / 'key.pem'
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    kp.chmod(0o600)
    return cp, kp, sha(cert.public_bytes(serialization.Encoding.DER))

class Share:
    def __init__(self, source, bind, port, advertise, log=print):
        self.source = private_path(source)
        if not self.source.exists():
            raise ValueError('Select an existing file or folder')
        self.base = self.source.parent if self.source.is_file() else self.source
        paths = [self.source] if self.source.is_file() else sorted(self.source.rglob('*'))
        self.files = []
        folded = set()
        for p in paths:
            private_path(p)
            if p.is_dir():
                continue
            if not p.is_file():
                raise ValueError('Only regular files supported')
            name = p.relative_to(self.base).as_posix()
            relative(name)
            if name.casefold() in folded:
                raise ValueError('Case-conflicting filenames')
            folded.add(name.casefold())
            st = p.stat()
            blocks = []
            h = hashlib.sha256()
            with p.open('rb') as f:
                while b := f.read(CHUNK):
                    h.update(b)
                    blocks.append(sha(b))
            if (st.st_size, st.st_mtime_ns) != (p.stat().st_size, p.stat().st_mtime_ns):
                raise ValueError('Source changed while indexing')
            self.files.append(dict(path=name, size=st.st_size, hash=h.hexdigest(), blocks=blocks, mtime=st.st_mtime_ns))
            log('Indexed ' + name)
        public = [{k: v for k, v in f.items() if k != 'mtime'} for f in self.files]
        self.identity = sha(json.dumps(public, sort_keys=True).encode())
        self.token = secrets.token_urlsafe(32)
        self.stop_event = threading.Event()
        cp, kp, pin = certificate(Path.home() / '.p2peeonme' / 'sessions' / secrets.token_hex(12))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(cp, kp)
        owner = self
        class Handler(socketserver.BaseRequestHandler):
            def handle(s):
                try:
                    s.request.settimeout(20)
                    with ctx.wrap_socket(s.request, server_side=True) as conn:
                        h, payload = recv(conn)
                        token = h.get('token', '')
                        if payload or not isinstance(token, str) or not token.isascii() or not secrets.compare_digest(token, owner.token):
                            raise ValueError('Access denied')
                        if owner.stop_event.is_set():
                            raise ValueError('Share stopped')
                        if h.get('op') == 'info':
                            send(conn, dict(ok=True, identity=owner.identity, count=len(public), chunk=CHUNK))
                            return
                        i = h.get('file')
                        if type(i) is not int or not 0 <= i < len(public):
                            raise ValueError('Invalid file')
                        row = public[i]
                        if h.get('op') == 'file':
                            send(conn, dict(ok=True, path=row['path'], size=row['size'], hash=row['hash'], count=len(row['blocks'])))
                            return
                        j = h.get('block')
                        if type(j) is not int or not 0 <= j < len(row['blocks']):
                            raise ValueError('Invalid chunk')
                        if h.get('op') == 'hash':
                            send(conn, dict(ok=True, hash=row['blocks'][j]))
                            return
                        if h.get('op') != 'get':
                            raise ValueError('Unknown operation')
                        p = private_path(owner.base / row['path'])
                        with p.open('rb') as f:
                            st = os.fstat(f.fileno())
                            if (st.st_size, st.st_mtime_ns) != (row['size'], owner.files[i]['mtime']):
                                raise ValueError('Source changed; re-share')
                            f.seek(j * CHUNK)
                            raw = f.read(min(CHUNK, row['size'] - j * CHUNK))
                        if sha(raw) != row['blocks'][j]:
                            raise ValueError('Source checksum changed')
                        packed = zlib.compress(raw, 3)
                        compressed = len(packed) + 32 < len(raw)
                        if owner.stop_event.is_set():
                            raise ValueError('Share stopped')
                        send(conn, dict(ok=True, hash=sha(raw), codec='zlib' if compressed else 'raw', n=len(raw)), packed if compressed else raw)
                except (OSError, ValueError, TypeError, KeyError):
                    pass
        class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
            allow_reuse_address = True
            daemon_threads = True
        self.server = Server((bind, port), Handler)
        value = dict(host=advertise, port=self.server.server_address[1], pin=pin, token=self.token)
        self.invitation = 'pee1.' + base64.urlsafe_b64encode(json.dumps(value).encode()).decode()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
    def stop(self):
        self.stop_event.set()
        self.server.shutdown()
        self.server.server_close()

class Client:
    def __init__(self, code):
        if not code.startswith('pee1.') or len(code) > 4096:
            raise ValueError('Invalid invitation')
        self.inv = json.loads(base64.urlsafe_b64decode(code[5:]))
        if not isinstance(self.inv, dict):
            raise ValueError('Invalid invitation')
    def request(self, op, **fields):
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.minimum_version = ssl.TLSVersion.TLSv1_3
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        with socket.create_connection((self.inv['host'], int(self.inv['port'])), timeout=20) as raw:
            with c.wrap_socket(raw, server_hostname=None) as conn:
                if not secrets.compare_digest(sha(conn.getpeercert(binary_form=True)), self.inv['pin']):
                    raise ValueError('Certificate pin mismatch')
                send(conn, dict(op=op, token=self.inv['token'], **fields))
                h, p = recv(conn)
                if h.get('ok') is not True:
                    raise ValueError('Peer rejected request')
                return h, p

def decode(h, p, n):
    if h.get('n') != n:
        raise ValueError('Unexpected chunk size')
    if h.get('codec') == 'raw':
        raw = p
    elif h.get('codec') == 'zlib':
        d = zlib.decompressobj()
        raw = d.decompress(p, n + 1)
        if len(raw) > n or d.unconsumed_tail or not d.eof or d.unused_data:
            raise ValueError('Unsafe compressed chunk')
    else:
        raise ValueError('Unknown codec')
    if len(raw) != n:
        raise ValueError('Wrong decoded length')
    return raw

def download(code, destination, workers=4, log=print, stop=None):
    stop = stop or threading.Event()
    workers = int(workers)
    if not 1 <= workers <= 8:
        raise ValueError('Use 1..8 workers')
    client = Client(code)
    info, _ = client.request('info')
    identity = info.get('identity')
    if not isinstance(identity, str) or len(identity) != 64 or any(c not in '0123456789abcdef' for c in identity):
        raise ValueError('Invalid identity')
    count = info.get('count')
    if type(count) is not int or not 0 <= count <= 1000000:
        raise ValueError('Manifest file count exceeds prototype limit')
    out = private_path(Path(destination) / ('P2PEEONME-' + identity[:16]))
    out.mkdir(parents=True, exist_ok=True)
    state = private_path(out / '.p2peeonme-partials')
    state.mkdir(exist_ok=True)
    payload = restored = 0
    seen = set()
    for i in range(count):
        if stop.is_set():
            raise ValueError('Paused. Repeat with the same output to resume.')
        row, _ = client.request('file', file=i)
        relative(row['path'])
        size, blocks = row.get('size'), row.get('count')
        if type(size) is not int or size < 0 or type(blocks) is not int or blocks != (size + CHUNK - 1) // CHUNK:
            raise ValueError('Invalid manifest sizes')
        if row['path'].casefold() in seen or row['path'].split('/')[0].casefold() == '.p2peeonme-partials':
            raise ValueError('Conflicting path')
        seen.add(row['path'].casefold())
        target = private_path(out / row['path'])
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if target.is_file() and target.stat().st_size == size and filehash(target) == row['hash']:
                log('Already verified: ' + row['path'])
                continue
            raise ValueError('Refusing to overwrite: ' + str(target))
        part = private_path(state / (str(i) + '.part'))
        if not part.exists():
            with part.open('xb') as f:
                f.truncate(size)
        if part.stat().st_size != size:
            raise ValueError('Partial size mismatch')
        def chunk(j):
            if stop.is_set():
                raise ValueError('Paused')
            expected, _ = Client(code).request('hash', file=i, block=j)
            n = min(CHUNK, size - j * CHUNK)
            with part.open('rb') as f:
                f.seek(j * CHUNK)
                current = f.read(n)
            if sha(current) == expected['hash']:
                return 0, 0
            h, p = Client(code).request('get', file=i, block=j)
            raw = decode(h, p, n)
            if sha(raw) != expected['hash'] or h.get('hash') != expected['hash']:
                raise ValueError('Chunk checksum failed')
            if stop.is_set():
                raise ValueError('Paused')
            with part.open('r+b') as f:
                f.seek(j * CHUNK)
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            return len(p), n
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for start in range(0, blocks, workers * 2):
                for a, b in pool.map(chunk, range(start, min(blocks, start + workers * 2))):
                    payload += a
                    restored += b
                log(f'{row["path"]}: {min(start + workers * 2, blocks)}/{blocks} chunks verified')
        if filehash(part) != row['hash']:
            raise ValueError('Whole-file checksum failed')
        os.link(part, target)
        part.unlink()
        log('Verified: ' + row['path'])
    result = dict(output=str(out), payload_bytes=payload, downloaded_original_bytes=restored)
    log('Complete: ' + str(out))
    return result

def gui():
    import tkinter as tk
    from tkinter import ttk, filedialog
    root = tk.Tk()
    root.title('P2PEEONME — experimental file transfer')
    root.geometry('900x730')
    events = queue.Queue()
    sharing, busy, receiving = [None], [False], [False]
    stop = threading.Event()
    outer = ttk.Frame(root, padding=18)
    outer.pack(fill='both', expand=True)
    ttk.Label(outer, text='P2PEEONME', font=('', 26, 'bold')).pack(anchor='w')
    ttk.Label(outer, text='Rebuilt experimental source • Direct TLS • Verified chunks • Resume').pack(anchor='w')
    ttk.Label(outer, text='LAN / trusted VPN only. No automatic pairing, relay or WAN bonding.', wraplength=850).pack(anchor='w', pady=8)
    tabs = ttk.Notebook(outer)
    tabs.pack(fill='x')
    a, b = ttk.Frame(tabs, padding=12), ttk.Frame(tabs, padding=12)
    tabs.add(a, text='Send')
    tabs.add(b, text='Receive')
    src, host, bind = tk.StringVar(), tk.StringVar(value='127.0.0.1'), tk.StringVar(value='127.0.0.1')
    dest, workers = tk.StringVar(value=str(Path.home() / 'Downloads')), tk.IntVar(value=4)
    def entry(parent, label, var):
        ttk.Label(parent, text=label).pack(anchor='w')
        ttk.Entry(parent, textvariable=var).pack(fill='x', pady=(0, 6))
    entry(a, 'Selected file or folder', src)
    row = ttk.Frame(a)
    row.pack(fill='x')
    ttk.Button(row, text='Choose file', command=lambda: src.set(filedialog.askopenfilename())).pack(side='left')
    ttk.Button(row, text='Choose folder', command=lambda: src.set(filedialog.askdirectory())).pack(side='left', padx=6)
    entry(a, 'Sender address reachable by your friend', host)
    entry(a, 'Listen IP (loopback, LAN/VPN IP or 0.0.0.0)', bind)
    invitation = tk.Text(a, height=4, wrap='char')
    def log(s):
        events.put(str(s))
    def work(fn):
        def run():
            try:
                fn()
            except Exception as e:
                log('Error: ' + str(e))
        threading.Thread(target=run, daemon=True).start()
    def start():
        if busy[0] or sharing[0]:
            log('Sharing already active or preparing')
            return
        values = src.get(), bind.get(), host.get()
        busy[0] = True
        def run():
            try:
                log('Indexing selected source...')
                s = Share(values[0], values[1], 47831, values[2], log)
                sharing[0] = s
                events.put(('invite', s.invitation))
            finally:
                busy[0] = False
        work(run)
    def halt():
        if sharing[0]:
            s = sharing[0]
            sharing[0] = None
            work(s.stop)
            log('Sharing stopped; future requests revoked.')
    ttk.Button(a, text='Index and start sharing', command=start).pack(anchor='w', pady=6)
    ttk.Button(a, text='Stop sharing', command=halt).pack(anchor='w')
    ttk.Label(a, text='Secret invitation — send privately').pack(anchor='w')
    invitation.pack(fill='x')
    def copy():
        root.clipboard_clear()
        root.clipboard_append(invitation.get('1.0', 'end').strip())
    ttk.Button(a, text='Copy invitation', command=copy).pack(anchor='w', pady=4)
    ttk.Label(b, text='Paste invitation').pack(anchor='w')
    code = tk.Text(b, height=4, wrap='char')
    code.pack(fill='x')
    entry(b, 'Destination (local hard-link-capable filesystem)', dest)
    ttk.Button(b, text='Choose destination', command=lambda: dest.set(filedialog.askdirectory())).pack(anchor='w')
    ttk.Label(b, text='Parallel workers (not a promised speed boost)').pack(anchor='w')
    ttk.Spinbox(b, from_=1, to=8, textvariable=workers, width=5).pack(anchor='w')
    def receive():
        if receiving[0]:
            log('A receive job is already running')
            return
        c, d, w = code.get('1.0', 'end').strip(), dest.get(), workers.get()
        stop.clear()
        receiving[0] = True
        def run():
            try:
                download(c, d, w, log, stop)
            finally:
                receiving[0] = False
        work(run)
    ttk.Button(b, text='Download / resume', command=receive).pack(anchor='w', pady=6)
    ttk.Button(b, text='Pause safely', command=stop.set).pack(anchor='w')
    logbox = tk.Text(outer, height=10, wrap='word')
    logbox.pack(fill='both', expand=True, pady=10)
    def poll():
        try:
            for _ in range(100):
                e = events.get_nowait()
                if isinstance(e, tuple):
                    invitation.delete('1.0', 'end')
                    invitation.insert('1.0', e[1])
                else:
                    logbox.insert('end', e + '\n')
                    logbox.see('end')
        except queue.Empty:
            pass
        root.after(100, poll)
    root.after(100, poll)
    root.mainloop()

def main():
    p = argparse.ArgumentParser(description='P2PEEONME rebuilt experimental transfer')
    s = p.add_subparsers(dest='command')
    s.add_parser('gui')
    a = s.add_parser('send')
    a.add_argument('source')
    a.add_argument('--bind', default='127.0.0.1')
    a.add_argument('--host', default='127.0.0.1')
    a.add_argument('--port', type=int, default=47831)
    b = s.add_parser('receive')
    b.add_argument('invitation')
    b.add_argument('destination')
    b.add_argument('--workers', type=int, default=4)
    args = p.parse_args()
    if args.command in (None, 'gui'):
        gui()
    elif args.command == 'receive':
        print(json.dumps(download(args.invitation, args.destination, args.workers), indent=2))
    else:
        share = Share(args.source, args.bind, args.port, args.host)
        print(share.invitation, flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            share.stop()

if __name__ == '__main__':
    main()
