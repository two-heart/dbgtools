import gdb
from typing import Sequence, Callable, Optional
from dbgtools.main import get_pie_base
from dbgtools.logger import Logger


def get_all_breakpoints() -> Sequence[gdb.Breakpoint]:
    return gdb.breakpoints()


def get_breakpoints_with_location(location):
    return list(filter(lambda b: b.location == location, get_all_breakpoints()))


def convert_to_gdb_bp_str(ptr: Optional[int] = None,
                          func_name: Optional[str] = None,
                          offset: Optional[int] = None) -> str:
    if ptr is not None:
        assert func_name is None and offset is None
        return f"*{hex(ptr)}"
    elif func_name is not None and offset is not None:
        return f"*({func_name}+{hex(offset)})"
    else:
        msg = "Breakpoint string has to consist of either <pointer> or " \
               + "<func_name, offset>"
        raise ValueError(msg)


class CustomBreakpoint(gdb.Breakpoint):
    _action_funcs: list[Callable[[], None]]
    _explicit_stop: bool

    def __init__(self,
                 bp_str: str,
                 action_funcs: Optional[list[Callable[[], None]]] = None,
                 enabled_default: bool = True,
                 explicit_stop: bool = False,
                 temporary: bool = False):
        super().__init__(bp_str, temporary=temporary)
        if action_funcs is None:
            action_funcs = []
        self._make_unique()
        self._bp_str = bp_str
        self.enabled = enabled_default
        self._explicit_stop = explicit_stop
        self._action_funcs = action_funcs
        self._cond_func = None

    @classmethod
    def create_pt_bp(cls, ptr, *args, **kwargs):
        return cls(convert_to_gdb_bp_str(ptr=ptr), *args, **kwargs)

    @classmethod
    def create_pie_bp(cls, ptr, *args, **kwargs):
        return cls(convert_to_gdb_bp_str(ptr=get_pie_base() + ptr),
                   *args, **kwargs)

    @classmethod
    def create_func_off_bp(cls, func_name, offset, *args, **kwargs):
        return cls(convert_to_gdb_bp_str(func_name=func_name, offset=offset),
                   *args, **kwargs)

    def _make_unique(self):
        for bp in get_breakpoints_with_location(self.location):
            if bp.number != self.number:
                bp.delete()

    def set_condition_func(self, cond_func):
        self._cond_func = cond_func

    def reset_condition_func(self):
        self._cond_func = None

    def stop(self):
        for bp_stop_func in self._action_funcs:
            bp_stop_func()
        if self._explicit_stop:
            return True
        if self._cond_func is not None:
            return self._cond_func()
        return False


class LogBreakpoint(CustomBreakpoint):
    logger_func: Callable[[], bytes]

    def __init__(self,
                 bp_str: str,
                 logger_func: Callable[[], bytes],
                 action_funcs: Optional[list[Callable[[], None]]] =None,
                 enabled_default: bool = True,
                 explicit_stop: bool = False,
                 temporary: bool = False):
        super().__init__(bp_str,
                         action_funcs,
                         enabled_default,
                         explicit_stop,
                         temporary)
        self._logger_func = logger_func

    def stop(self):
        logger = Logger.get_instance()
        log = self._logger_func()
        if len(log) != 0:
            logger.log_line(log)
        return super().stop()


class ActionBreakpoint(CustomBreakpoint):
    def __init__(self,
                 bp_str: str,
                 action_funcs: Optional[list[Callable[[], None]]] ,
                 explicit_stop: bool = False):
        super().__init__(bp_str,
                         action_funcs,
                         enabled_default=True,
                         explicit_stop=explicit_stop,
                         temporary=False)


# TODO: cleanup
class TraceBreakpoint(CustomBreakpoint):
    def __init__(self, bp_str: str, trace_function, explicit_stop=False):
        super().__init__(bp_str, [self._do_trace], enabled_default=True, explicit_stop=explicit_stop, temporary=False)
        self._trace_func = trace_function
        self._last_traces = []
        self._traces = []

    def get_traces(self):
        return self._traces

    def get_last_traces(self):
        return self._last_traces

    def reset_last_traces(self):
        self._last_traces = []

    def _do_trace(self):
        trace = self._trace_func()
        self._last_traces.append(trace)
        self._traces.append(trace)

    def reset(self):
        self._traces = []
        self._last_traces = []
