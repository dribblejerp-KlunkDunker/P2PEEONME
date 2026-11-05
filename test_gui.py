"""Real-display GUI smoke test. File-dialog results are controlled.

Uses the actual Tk widgets and transfer implementation. A pass does not
establish native dialog, Chromebook, cross-machine, or WAN compatibility.
"""
import contextlib
from pathlib import Path
import tempfile
import time
import traceback
import tkinter as tk
from tkinter import ttk, filedialog
import unittest
from unittest import mock

import p2peeonme as app


def descendants(widget):
    result = []
    for child in widget.winfo_children():
        result.append(child)
        result.extend(descendants(child))
    return result


def destroy_safely(root):
    with contextlib.suppress(tk.TclError):
        root.destroy()


class DesktopGuiTests(unittest.TestCase):
    def test_window_controls_and_local_transfer(self):
        roots, shares, failures, checks = [], [], [], []
        original_tk, original_share = tk.Tk, app.Share
        deadline = time.monotonic() + 60
        phase = ['startup']
        callbacks = []

        def record_failure(error):
            failures.append(f'{phase[0]}: {error}')
            for root in roots:
                with contextlib.suppress(tk.TclError):
                    root.quit()

        def callback_exception(kind, value, trace):
            record_failure(''.join(traceback.format_exception(kind, value, trace)))

        def schedule(fn):
            def guarded():
                try:
                    if time.monotonic() >= deadline:
                        raise AssertionError(f'Timed out waiting for {phase[0]}')
                    fn()
                except Exception:
                    record_failure(traceback.format_exc())
            callbacks.append(roots[0].after(100, guarded))

        def factory(*args, **kwargs):
            root = original_tk(*args, **kwargs)
            roots.append(root)
            root.report_callback_exception = callback_exception
            callbacks.append(root.after(60000, lambda: record_failure('GUI watchdog timeout')))
            schedule(begin)
            return root

        def tracked_share(*args, **kwargs):
            share = original_share(*args, **kwargs)
            shares.append(share)
            return share

        def button(parent, label):
            matches = [w for w in descendants(parent)
                       if isinstance(w, ttk.Button) and str(w.cget('text')) == label]
            self.assertEqual(len(matches), 1, f'Expected one button: {label}')
            return matches[0]

        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory / 'gui-fixture.bin'
            data = b'P2PEEONME GUI functional fixture\n' * 1024
            source.write_bytes(data)
            destination = directory / 'received'
            destination.mkdir()

            def begin():
                root = roots[0]
                root.update_idletasks()
                if not root.winfo_ismapped():
                    schedule(begin)
                    return
                self.assertEqual(root.title(), 'P2PEEONME — experimental file transfer')
                notebook = next(w for w in descendants(root) if isinstance(w, ttk.Notebook))
                self.assertEqual([notebook.tab(t, 'text') for t in notebook.tabs()], ['Send', 'Receive'])
                self.notebook = notebook
                self.sender = notebook.nametowidget(notebook.tabs()[0])
                self.receiver = notebook.nametowidget(notebook.tabs()[1])
                entries = [w for w in descendants(self.sender) if isinstance(w, ttk.Entry)]
                self.assertEqual([w.get() for w in entries[1:]], ['127.0.0.1', '127.0.0.1'])
                with mock.patch.object(filedialog, 'askopenfilename', return_value=str(source)):
                    button(self.sender, 'Choose file').invoke()
                self.assertEqual(entries[0].get(), str(source))
                self.invitation = next(w for w in descendants(self.sender) if isinstance(w, tk.Text))
                tab_widgets = descendants(notebook)
                self.log = next(w for w in descendants(root)
                                if isinstance(w, tk.Text) and w not in tab_widgets)
                checks.append('window, branding, tabs, defaults, file selection')
                phase[0] = 'share startup'
                button(self.sender, 'Index and start sharing').invoke()
                schedule(wait_for_invitation)

            def assert_no_app_error():
                log = self.log.get('1.0', 'end')
                self.assertNotIn('Error:', log, 'Application reported an error: ' + log)
                return log

            def wait_for_invitation():
                assert_no_app_error()
                root = roots[0]
                code = self.invitation.get('1.0', 'end').strip()
                if not code:
                    schedule(wait_for_invitation)
                    return
                self.assertTrue(code.startswith('pee1.'))
                button(self.sender, 'Copy invitation').invoke()
                self.assertEqual(root.clipboard_get(), code)
                self.notebook.select(self.receiver)
                root.update_idletasks()
                self.assertEqual(str(self.notebook.select()), str(self.receiver))
                text = next(w for w in descendants(self.receiver) if isinstance(w, tk.Text))
                text.insert('1.0', code)
                with mock.patch.object(filedialog, 'askdirectory', return_value=str(destination)):
                    button(self.receiver, 'Choose destination').invoke()
                entry = next(w for w in descendants(self.receiver)
                             if isinstance(w, ttk.Entry) and not isinstance(w, ttk.Spinbox))
                self.assertEqual(entry.get(), str(destination))
                checks.append('real share startup, invitation, clipboard, destination')
                phase[0] = 'GUI-driven transfer'
                button(self.receiver, 'Download / resume').invoke()
                schedule(wait_for_completion)

            def wait_for_completion():
                log = assert_no_app_error()
                if 'Complete:' not in log:
                    schedule(wait_for_completion)
                    return
                outputs = list(destination.glob('P2PEEONME-*/gui-fixture.bin'))
                self.assertEqual(len(outputs), 1)
                self.assertEqual(outputs[0].read_bytes(), data)
                button(self.receiver, 'Pause safely').invoke()
                self.notebook.select(self.sender)
                button(self.sender, 'Stop sharing').invoke()
                phase[0] = 'server shutdown'
                schedule(wait_for_shutdown)

            def wait_for_shutdown():
                assert_no_app_error()
                self.assertEqual(len(shares), 1)
                if shares[0].thread.is_alive() or shares[0].server.fileno() != -1:
                    schedule(wait_for_shutdown)
                    return
                checks.append('verified TLS output, idle pause, completed server shutdown')
                roots[0].quit()

            try:
                with mock.patch.object(tk, 'Tk', side_effect=factory), mock.patch.object(app, 'Share', side_effect=tracked_share):
                    app.gui()
            finally:
                for share in shares:
                    try:
                        if share.server.fileno() != -1:
                            share.stop()
                    except Exception:
                        failures.append('Cleanup: ' + traceback.format_exc())
                for root in roots:
                    for callback in callbacks:
                        with contextlib.suppress(tk.TclError):
                            root.after_cancel(callback)
                    destroy_safely(root)
            self.assertFalse(failures, '\n'.join(failures))
            self.assertEqual(len(checks), 3, 'Not all GUI stages completed')
            for check in checks:
                print('PASS:', check)


if __name__ == '__main__':
    unittest.main(verbosity=2)
