#!/usr/bin/env python3
"""Smoke-test decompile.py's GUI without a display.

tkinter is unavailable in this environment, so a permissive fake is injected
into sys.modules before the App class is constructed.  This exercises the real
GUI code paths - widget creation, the load handler, the start handler, the
log-drain loop - and would catch typos or undefined attributes that a visual
check would otherwise be needed for.

It does NOT verify visual layout, which cannot be checked here.
"""

import os
import sys
import types
import time

HERE = "/home/user/help-me-"
sys.path.insert(0, HERE)

CALLS = []


class Fake(object):
    """Records every attribute access and call, and returns another Fake."""

    def __init__(self, name="fake"):
        object.__setattr__(self, "_name", name)

    def __getattr__(self, key):
        if key.startswith("__") and key.endswith("__"):
            raise AttributeError(key)
        return Fake("%s.%s" % (object.__getattribute__(self, "_name"), key))

    def __setattr__(self, key, value):
        object.__setattr__(self, key, value)

    def __call__(self, *args, **kwargs):
        CALLS.append((object.__getattribute__(self, "_name"), args, kwargs))
        name = object.__getattribute__(self, "_name")
        # after() must not actually schedule, or the drain loop would spin.
        if name.endswith(".after"):
            return None
        return Fake("%s()" % name)


class FakeStringVar(object):
    def __init__(self, value="", **kw):
        self._v = value

    def get(self):
        return self._v

    def set(self, v):
        self._v = v


class FakeText(Fake):
    def __init__(self, *a, **kw):
        Fake.__init__(self, "Text")
        self.content = []
        self._state = "normal"

    def insert(self, index, text, *tags):
        self.content.append((text, tags))

    def delete(self, *a):
        self.content = []

    def configure(self, **kw):
        if "state" in kw:
            self._state = kw["state"]

    def see(self, *a):
        pass

    def tag_configure(self, *a, **kw):
        pass

    def get(self, *a):
        return "\n".join(t for t, _ in self.content)


def install_fake_tkinter(chosen_file):
    tk = types.ModuleType("tkinter")
    tk.Tk = lambda *a, **kw: Fake("Tk")
    tk.Text = FakeText
    tk.StringVar = FakeStringVar
    tk.Tcl = lambda *a, **kw: object()
    tk.TkVersion = 8.6
    tk.END = "end"

    ttk = types.ModuleType("tkinter.ttk")

    class FakeStyle(object):
        def __init__(self, *a, **kw):
            pass

        def theme_use(self, *a):
            pass

    ttk.Style = FakeStyle
    for widget in ("Frame", "Label", "Button", "Entry", "Progressbar",
                   "Scrollbar", "Separator", "Notebook"):
        setattr(ttk, widget, lambda *a, **kw: Fake(widget))
    tk.ttk = ttk

    fd = types.ModuleType("tkinter.filedialog")
    fd.askopenfilename = lambda *a, **kw: chosen_file
    fd.askdirectory = lambda *a, **kw: "/tmp"

    mb = types.ModuleType("tkinter.messagebox")
    mb.showinfo = lambda *a, **kw: CALLS.append(("showinfo", a, kw))
    mb.showerror = lambda *a, **kw: CALLS.append(("showerror", a, kw))
    mb.askyesno = lambda *a, **kw: True

    sys.modules["tkinter"] = tk
    sys.modules["tkinter.ttk"] = ttk
    sys.modules["tkinter.filedialog"] = fd
    sys.modules["tkinter.messagebox"] = mb
    return tk


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else \
        "/home/user/work/artifacts/specimen_app_accelerated"
    outdir = "/tmp/gui_test_out"

    install_fake_tkinter(target)

    import decompile

    print("1. constructing App ...")
    tk = sys.modules["tkinter"]
    app = decompile.App(tk.Tk())
    print("   OK - window built without error")

    print("2. simulating 'Load EXE' ...")
    app.load_file()
    label = app.lbl_file._v if hasattr(app.lbl_file, "_v") else None
    print("   target set to: %s" % app.target)
    assert app.target == target, "load_file did not store the target"
    assert app.var_out.get(), "output path was not defaulted"
    print("   output defaulted to: %s" % app.var_out.get())

    print("3. simulating 'Start' ...")
    app.var_out.set(outdir)
    app.start()
    assert app.running, "start() did not set running"
    print("   worker thread started: %s" % app.worker.is_alive())

    print("4. pumping the log-drain loop until finished ...")
    deadline = time.time() + 120
    pumps = 0
    while app.running and time.time() < deadline:
        app._check_done()
        pumps += 1
        time.sleep(0.05)
    assert not app.running, "pipeline did not finish within the timeout"
    print("   finished after %d pumps" % pumps)

    print("5. checking the log actually received lines ...")
    lines = len(app.log_widget.content)
    print("   log lines rendered: %d" % lines)
    assert lines > 5, "nothing was written to the log widget"

    joined = "\n".join(t for t, _ in app.log_widget.content)
    for expecting in ("Starting extraction", "modules identified", "Done in"):
        assert expecting in joined, "log missing %r" % expecting
    print("   log contains the expected phases")

    print("6. checking results on disk ...")
    assert os.path.isdir(outdir), "results folder was not created"
    names = sorted(os.listdir(outdir))
    print("   %s" % names)
    for required in ("START_HERE.txt", "report.txt", "strings.txt",
                     "evidence.txt", "prompt.txt", "skeleton"):
        assert required in names, "missing output %r" % required

    sizes = os.listdir(os.path.join(outdir, "skeleton"))
    print("   skeleton: %s" % sizes)

    print()
    print("=" * 60)
    print("GUI SMOKE TEST PASSED")
    print("=" * 60)
    print("Exercised: window construction, load handler, start handler,")
    print("background thread, log drain, and every output file.")
    print("NOT verified: visual layout (no display available here).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
