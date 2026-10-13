"""Wait for interrupted child processes to finish their own cleanup."""
import contextlib
import os
import signal
import subprocess


class RunInterrupted(KeyboardInterrupt):
    def __init__(self, signum):
        self.signum = signum
        self.child_returncode = None
        super().__init__('signal_' + signal.Signals(signum).name)


def install_signal_handlers():
    def interrupt(signum, _frame):
        raise RunInterrupted(signum)
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupt)


@contextlib.contextmanager
def finish_cleanup():
    # A Python handler resets to the default on exec; SIG_IGN would be inherited
    # by cleanup commands and make their own timeout termination ineffective.
    previous = {s: signal.signal(s, lambda *_: None) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def stop_child(proc, signum, grace):
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signum)
        except ProcessLookupError:
            pass
    try:
        return proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return proc.wait()


def execute(args, *, env, output, timeout, interrupt_grace):
    # Separate groups let the parent signal its nested harness without also
    # interrupting the Compose commands that harness starts for cleanup.
    pending = []
    previous = {s: signal.signal(s, lambda signum, _frame: pending.append(signum)) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        proc = subprocess.Popen(args, env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    try:
        for signum in pending:
            handler = previous[signum]
            if callable(handler):
                handler(signum, None)
            elif handler != signal.SIG_IGN:
                raise RunInterrupted(signum)
        return proc.wait(timeout=timeout)
    except BaseException as exc:
        with finish_cleanup():
            signum = exc.signum if isinstance(exc, RunInterrupted) else signal.SIGTERM
            code = stop_child(proc, signum, interrupt_grace)
            if isinstance(exc, RunInterrupted):
                exc.child_returncode = code
        raise
