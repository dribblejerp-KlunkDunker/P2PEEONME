"""Real Tk GUI smoke test; requires a display (Xvfb on Linux).

Exercises actual application callbacks and local TLS transfer. File-picker
return values are controlled so CI does not need a human dialog selection.
This does not establish native file-dialog, WAN, or Chromebook compatibility.
"""
import tempfile
import time
import tkinter as tk
from tkinter import ttk, filedialog
import unittest
from unittest import mock
from pathlib import Path

import p2peeonme as app


def descendants(widget):
    result = []
    for child in widget.winfo_children():
        result.append(child)
        result.extend(descendants(child))
    return result


class DesktopGuiTests(unittest.TestCase):
    def test_window_controls_and_local_transfer(self):
        failures, roots, shares = [], [], []
        checks = []
        original_tk = tk.Tk
        original_share = app.Share
        deadline = time.monotonic() + 30
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory / 'gui-fixture.bin'
            data = b'P2PEEONME GUI functional fixture\n' * 1024
            source.write_bytes(data)
            destination = directory / 'received'
            destination.mkdir()

            def tracked_share(*args, **kwargs):
                share = original_share(*args, **kwargs)
                shares.append(share)
                return share

            def fail(error):
                failures.append(str(error))
                for root in roots:
                    if root.winfo_exists():
                        root.destroy()

            def guarded(callback):
                def run():
                    try:
                        if time.monotonic() > deadline:
                            raise AssertionError('GUI smoke test timed out')
                        callback()
                    except Exception as error:
                        fail(error)
                return run

            def factory(*args, **kwargs):
                root = original_tk(*args, **kwargs)
                roots.append(root)
                root.report_callback_exception = lambda kind, value, trace: fail(value)
                root.after(150, guarded(begin))
                root.after(30000, lambda: fail('GUI watchdog timeout'))
                return root

            def button(parent, label):
                return next(w for w in descendants(parent)
                            if isinstance(w, ttk.Button) and w.cget('text') == label)

            def begin():
                root = roots[0]
                root.update_idletasks()
                self.assertEqual(root.title(), 'P2PEEONME — experimental file transfer')
                self.assertTrue(root.winfo_ismapped())
                notebook = next(w for w in descendants(root) if isinstance(w, ttk.Notebook))
                self.assertEqual([notebook.tab(t, 'text') for t in notebook.tabs()], ['Send', 'Receive'])
                sender = notebook.nametowidget(notebook.tabs()[0])
                receiver = notebook.nametowidget(notebook.tabs()[1])
                entries = [w for w in descendants(sender) if isinstance(w, ttk.Entry)]
                self.assertEqual(entries[1].get(), '127.0.0.1')
                self.assertEqual(entries[2].get(), '127.0.0.1')
                with mock.patch.object(filedialog, 'askopenfilename', return_value=str(source)):
                    button(sender, 'Choose file').invoke()
                self.assertEqual(entries[0].get(), str(source))
                self.sender, self.receiver, self.notebook = sender, receiver, notebook
                self.invitation = next(w for w in descendants(sender) if isinstance(w, tk.Text))
                self.log = next(w for w in descendants(root) if isinstance(w, tk.Text)
                                and w not in descendants(notebook))
                checks.append('window, branding, tabs, defaults, file selection')
                button(sender, 'Index and start sharing').invoke()
                root.after(100, guarded(wait_for_invitation))

            def wait_for_invitation():
                root = roots[0]
                code = self.invitation.get('1.0', 'end').strip()
                if not code:
                    if 'Error:' in self.log.get('1.0', 'end'):
                        raise AssertionError('Sharing failed: ' + self.log.get('1.0', 'end'))
                    root.after(100, guarded(wait_for_invitation))
                    return
                self.assertTrue(code.startswith('pee1.'))
                button(self.sender, 'Copy invitation').invoke()
                self.assertEqual(root.clipboard_get(), code)
                self.notebook.select(self.receiver)
                root.update_idletasks()
                self.assertEqual(self.notebook.select(), str(self.receiver))
                text = next(w for w in descendants(self.receiver) if isinstance(w, tk.Text))
                text.insert('1.0', code)
                with mock.patch.object(filedialog, 'askdirectory', return_value=str(destination)):
                    button(self.receiver, 'Choose destination').invoke()
                entry = next(w for w in descendants(self.receiver)
                             if isinstance(w, ttk.Entry) and not isinstance(w, ttk.Spinbox))
                self.assertEqual(entry.get(), str(destination))
                checks.append('real share startup, invitation, clipboard, tab switch, destination')
                button(self.receiver, 'Download / resume').invoke()
                root.after(100, guarded(wait_for_completion))

            def wait_for_completion():
                root = roots[0]
                log = self.log.get('1.0', 'end')
                if 'Error:' in log:
                    raise AssertionError('GUI transfer failed: ' + log)
                if 'Complete:' not in log:
                    root.after(100, guarded(wait_for_completion))
                    return
                outputs = list(destination.glob('P2PEEONME-*/gui-fixture.bin'))
                self.assertEqual(len(outputs), 1)
                self.assertEqual(outputs[0].read_bytes(), data)
                button(self.receiver, 'Pause safely').invoke()
                self.notebook.select(self.sender)
                button(self.sender, 'Stop sharing').invoke()
                checks.append('GUI-driven TLS transfer, exact output, idle pause, stop sharing callback')
                root.after(700, root.destroy)

            try:
                with mock.patch.object(tk, 'Tk', side_effect=factory), mock.patch.object(app, 'Share', side_effect=tracked_share):
                    app.gui()
            finally:
                for share in shares:
                    share.stop()
                for root in roots:
                    try:
                        root.destroy()
                    except tk.TclError:
                        pass
            self.assertFalse(failures, '\n'.join(failures))
            self.assertEqual(len(checks), 3, 'GUI did not finish all stages')
            for check in checks:
                print('PASS:', check)


if __name__ == '__main__':
    unittest.main(verbosity=2)
