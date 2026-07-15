"""
Tests for the SIGTERM/SIGHUP cleanup handler — no i2pd, no network.

We exercise the handler's decision logic directly (stop, then chain or
re-deliver) with stop()/os.kill/signal.signal mocked, so the test process is
never actually signalled. Real installation is checked only for its
main-thread guard.
"""

from __future__ import annotations

import signal
import threading
from unittest import mock

import pytest

import basic_i2p


@pytest.fixture(autouse=True)
def _isolate_signal_state():
    """Snapshot and restore module signal globals + real dispositions."""
    saved_flag = basic_i2p._signals_installed
    saved_prev = dict(basic_i2p._prev_signal_handlers)
    real = {s: signal.getsignal(s) for s in basic_i2p._cleanup_signals()}
    yield
    basic_i2p._signals_installed = saved_flag
    basic_i2p._prev_signal_handlers = saved_prev
    for s, h in real.items():
        try:
            signal.signal(s, h)
        except (ValueError, OSError):
            pass


def test_handler_chains_to_previous_callable():
    calls = []
    prev = lambda signum, frame: calls.append(("prev", signum))  # noqa: E731
    basic_i2p._prev_signal_handlers = {int(signal.SIGTERM): prev}
    with mock.patch.object(basic_i2p, "stop") as stop, \
         mock.patch("signal.signal"), \
         mock.patch("os.kill") as kill:
        basic_i2p._handle_termination_signal(int(signal.SIGTERM), None)
    stop.assert_called_once()
    assert calls == [("prev", int(signal.SIGTERM))]
    kill.assert_not_called()  # chained, not re-delivered


def test_handler_redelivers_when_default():
    basic_i2p._prev_signal_handlers = {int(signal.SIGTERM): signal.SIG_DFL}
    with mock.patch.object(basic_i2p, "stop") as stop, \
         mock.patch("signal.signal"), \
         mock.patch("os.kill") as kill:
        basic_i2p._handle_termination_signal(int(signal.SIGTERM), None)
    stop.assert_called_once()
    kill.assert_called_once()  # re-raise for default terminate


def test_handler_respects_previous_ignore():
    basic_i2p._prev_signal_handlers = {int(signal.SIGTERM): signal.SIG_IGN}
    with mock.patch.object(basic_i2p, "stop") as stop, \
         mock.patch("signal.signal"), \
         mock.patch("os.kill") as kill:
        basic_i2p._handle_termination_signal(int(signal.SIGTERM), None)
    stop.assert_called_once()
    kill.assert_not_called()  # was ignored → keep running


def test_handler_stops_even_if_chain_raises():
    """stop() must run before we hand off, even if the prior handler throws."""
    def boom(signum, frame):
        raise RuntimeError("prev handler failed")
    basic_i2p._prev_signal_handlers = {int(signal.SIGTERM): boom}
    with mock.patch.object(basic_i2p, "stop") as stop, \
         mock.patch("signal.signal"), \
         mock.patch("os.kill"):
        with pytest.raises(RuntimeError):
            basic_i2p._handle_termination_signal(int(signal.SIGTERM), None)
    stop.assert_called_once()


def test_install_skips_on_worker_thread():
    basic_i2p._signals_installed = False
    before = signal.getsignal(signal.SIGTERM)
    done = threading.Event()

    def worker():
        basic_i2p._install_signal_handlers()
        done.set()

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    done.wait(1)
    assert basic_i2p._signals_installed is False
    assert signal.getsignal(signal.SIGTERM) is before  # untouched off-main-thread


def test_install_on_main_thread_sets_handler_and_saves_prev():
    basic_i2p._signals_installed = False
    basic_i2p._prev_signal_handlers = {}
    basic_i2p._install_signal_handlers()
    assert basic_i2p._signals_installed is True
    assert signal.getsignal(signal.SIGTERM) is basic_i2p._handle_termination_signal
    assert int(signal.SIGTERM) in basic_i2p._prev_signal_handlers
