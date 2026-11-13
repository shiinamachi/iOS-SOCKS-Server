"""Best-effort iOS helpers that work in both Pythonista and a-Shell."""

import ctypes
import logging
from ctypes import c_bool, c_char_p, c_long, c_void_p

logger = logging.getLogger("ios")


def _set_idle_timer_disabled_objc(disabled: bool) -> bool:
    """[[UIApplication sharedApplication] setIdleTimerDisabled:disabled] on
    the main thread, via plain Objective-C runtime calls (no objc_util).

    UIKit must only be touched from the main thread, so we build an
    NSInvocation and let the main thread run it. That way no Python code runs
    on the main thread, which keeps this safe inside a-Shell.
    """
    try:
        objc = ctypes.CDLL("/usr/lib/libobjc.A.dylib")
    except OSError:
        return False
    objc.objc_getClass.restype = c_void_p
    objc.objc_getClass.argtypes = [c_char_p]
    objc.sel_registerName.restype = c_void_p
    objc.sel_registerName.argtypes = [c_char_p]

    def msg(restype, *argtypes):
        # objc_msgSend must be called with the exact prototype on arm64.
        proto = ctypes.CFUNCTYPE(restype, c_void_p, c_void_p, *argtypes)
        return proto(("objc_msgSend", objc))

    sel = objc.sel_registerName
    ui_application = objc.objc_getClass(b"UIApplication")
    ns_invocation = objc.objc_getClass(b"NSInvocation")
    if not ui_application or not ns_invocation:
        return False  # not a UIKit app (e.g. desktop Python)
    app = msg(c_void_p)(ui_application, sel(b"sharedApplication"))
    if not app:
        return False
    setter = sel(b"setIdleTimerDisabled:")
    signature = msg(c_void_p, c_void_p)(
        app, sel(b"methodSignatureForSelector:"), setter
    )
    if not signature:
        return False
    invocation = msg(c_void_p, c_void_p)(
        ns_invocation, sel(b"invocationWithMethodSignature:"), signature
    )
    if not invocation:
        return False
    msg(None, c_void_p)(invocation, sel(b"setTarget:"), app)
    msg(None, c_void_p)(invocation, sel(b"setSelector:"), setter)
    flag = c_bool(disabled)
    msg(None, c_void_p, c_long)(
        invocation, sel(b"setArgument:atIndex:"), ctypes.addressof(flag), 2
    )
    msg(None)(invocation, sel(b"retainArguments"))
    msg(None, c_void_p, c_void_p, c_bool)(
        invocation,
        sel(b"performSelectorOnMainThread:withObject:waitUntilDone:"),
        sel(b"invoke"),
        None,
        False,
    )
    return True


def set_idle_timer_disabled(disabled: bool) -> bool:
    """Keep the screen from locking (and iOS from suspending the app) while
    the proxy runs. Returns True if it was applied."""
    try:
        # Pythonista
        import console
        from objc_util import on_main_thread

        on_main_thread(console.set_idle_timer_disabled)(disabled)
        return True
    except ImportError:
        pass
    except Exception as e:
        logger.info("Pythonista idle timer call failed: %s", e)
    try:
        # a-Shell (or any other UIKit app embedding Python)
        return _set_idle_timer_disabled_objc(disabled)
    except Exception as e:
        logger.info("Could not change the idle timer: %s: %s", type(e).__name__, e)
        return False
