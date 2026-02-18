import logging
import functools
import os
import sys
import time
import threading
import idaapi
import idc
from .rpc import McpToolError
from .zeromcp.jsonrpc import get_current_cancel_event, RequestCancelledError

# ============================================================================
# IDA Synchronization & Error Handling
# ============================================================================

ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))

if (ida_major > 9) or (ida_major == 9 and ida_minor >= 2):
    from PySide6.QtCore import QObject, QEvent, QCoreApplication
else:
    from PyQt5.QtCore import QObject, QEvent, QCoreApplication


class IDAError(McpToolError):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(Exception):
    pass


class CancelledError(RequestCancelledError):
    """Raised when a request is cancelled via notifications/cancelled."""

    pass


# ============================================================================
# Qt-based main-thread dispatch
# ============================================================================

class _FuncEvent(QEvent):
    TYPE = QEvent.Type(QEvent.registerEventType())
    __slots__ = ("func", "result", "done")

    def __init__(self, func, result, done):
        super().__init__(self.TYPE)
        self.func = func
        self.result = result
        self.done = done


class _Dispatcher(QObject):
    def event(self, e):
        if isinstance(e, _FuncEvent):
            old_batch = idc.batch(1)
            try:
                e.result["value"] = e.func()
            except Exception as exc:
                e.result["exc"] = exc
            finally:
                idc.batch(old_batch)
            e.done.set()
            return True
        return super().event(e)


# Created at import time (on the main thread during plugin load).
_dispatcher = _Dispatcher()


logger = logging.getLogger(__name__)
_TOOL_TIMEOUT_ENV = "IDA_MCP_TOOL_TIMEOUT_SEC"
_MIN_TOOL_TIMEOUT_SEC = 300.0
_DEFAULT_TOOL_TIMEOUT_SEC = _MIN_TOOL_TIMEOUT_SEC


def _enforce_min_timeout_seconds(timeout: float) -> float:
    # Preserve explicit "no timeout" behavior (<= 0), but clamp positives.
    if timeout <= 0:
        return timeout
    return max(timeout, _MIN_TOOL_TIMEOUT_SEC)


def _get_tool_timeout_seconds() -> float:
    value = os.getenv(_TOOL_TIMEOUT_ENV, "").strip()
    if value == "":
        return _DEFAULT_TOOL_TIMEOUT_SEC
    try:
        return _enforce_min_timeout_seconds(float(value))
    except ValueError:
        return _DEFAULT_TOOL_TIMEOUT_SEC


def _sync_wrapper(ff, mode=None):
    """Call ff on IDA's main thread via Qt event dispatch."""
    # Main thread: call directly.
    if idaapi.is_main_thread():
        old_batch = idc.batch(1)
        try:
            return ff()
        finally:
            idc.batch(old_batch)

    # Worker thread: post to Qt event loop, block until done.
    result: dict[str, object] = {}
    done = threading.Event()
    QCoreApplication.postEvent(_dispatcher, _FuncEvent(ff, result, done))
    done.wait()

    if "exc" in result:
        raise result["exc"]
    return result.get("value")


def _sync_wrapper_read(ff):
    """Like _sync_wrapper but uses MFF_READ for concurrent read access."""
    return _sync_wrapper(ff, mode=idaapi.MFF_READ)


def _normalize_timeout(value: object) -> float | None:
    if value is None:
        return None
    try:
        return _enforce_min_timeout_seconds(float(value))
    except (TypeError, ValueError):
        return None


def sync_wrapper(ff, timeout_override: float | None = None, mode=None):
    """Wrapper to enable timeout and cancellation during IDA synchronization.

    Note: Batch mode is now handled in _sync_wrapper to ensure it's always
    applied consistently for all synchronized operations.
    """
    # Capture cancel event from thread-local before execute_sync
    cancel_event = get_current_cancel_event()

    timeout = timeout_override
    if timeout is None:
        timeout = _get_tool_timeout_seconds()
    if timeout > 0 or cancel_event is not None:

        def timed_ff():
            # Calculate deadline when execution starts on IDA main thread,
            # not when the request was queued (avoids stale deadlines)
            deadline = time.monotonic() + timeout if timeout > 0 else None

            def profilefunc(frame, event, arg):
                # Check cancellation first (higher priority)
                if cancel_event is not None and cancel_event.is_set():
                    raise CancelledError("Request was cancelled")
                if deadline is not None and time.monotonic() >= deadline:
                    raise IDASyncError(f"Tool timed out after {timeout:.2f}s")

            old_profile = sys.getprofile()
            sys.setprofile(profilefunc)
            try:
                return ff()
            finally:
                sys.setprofile(old_profile)

        timed_ff.__name__ = ff.__name__
        return _sync_wrapper(timed_ff, mode=mode)
    return _sync_wrapper(ff, mode=mode)


def sync_wrapper_read(ff, timeout_override: float | None = None):
    """Read-mode wrapper to enable timeout and cancellation during synchronization."""
    cancel_event = get_current_cancel_event()

    timeout = timeout_override
    if timeout is None:
        timeout = _get_tool_timeout_seconds()
    if timeout > 0 or cancel_event is not None:

        def timed_ff():
            deadline = time.monotonic() + timeout if timeout > 0 else None

            def profilefunc(frame, event, arg):
                if cancel_event is not None and cancel_event.is_set():
                    raise CancelledError("Request was cancelled")
                if deadline is not None and time.monotonic() >= deadline:
                    raise IDASyncError(f"Tool timed out after {timeout:.2f}s")

            old_profile = sys.getprofile()
            sys.setprofile(profilefunc)
            try:
                return ff()
            finally:
                sys.setprofile(old_profile)

        timed_ff.__name__ = ff.__name__
        return _sync_wrapper_read(timed_ff)
    return _sync_wrapper_read(ff)


def idasync(f):
    """Run the function on the IDA main thread in write mode.

    Use for tools that modify IDA state.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(
            getattr(f, "__ida_mcp_timeout_sec__", None)
        )
        return sync_wrapper(ff, timeout_override)

    return wrapper


def idaread(f):
    """Run the function on the IDA main thread in READ mode.

    Allows concurrent execution with other idaread-decorated functions.
    Use for tools that only read IDA state.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(
            getattr(f, "__ida_mcp_timeout_sec__", None)
        )
        return sync_wrapper_read(ff, timeout_override)

    return wrapper


def tool_timeout(seconds: float):
    """Decorator to override per-tool timeout (seconds).

    IMPORTANT: Must be applied BEFORE @idasync (i.e., listed AFTER it)
    so the attribute exists when it captures the function in closure.

    Correct order:
        @tool
        @idasync
        @tool_timeout(300.0)  # innermost
        def my_func(...):
    """

    def decorator(func):
        setattr(func, "__ida_mcp_timeout_sec__", seconds)
        return func

    return decorator


def is_window_active():
    """Returns whether IDA is currently active."""
    # Source: https://github.com/OALabs/hexcopy-ida/blob/8b0b2a3021d7dc9010c01821b65a80c47d491b61/hexcopy.py#L30
    using_pyside6 = (ida_major > 9) or (ida_major == 9 and ida_minor >= 2)

    if using_pyside6:
        from PySide6 import QtWidgets
    else:
        from PyQt5 import QtWidgets

    app = QtWidgets.QApplication.instance()
    if app is None:
        return False
    return app.activeWindow() is not None
