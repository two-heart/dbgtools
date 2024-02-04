import gdb
from typing import Sequence, Callable, Optional
from dbgtools.main import get_pie_base
from dbgtools.logger import Logger


def get_all_breakpoints() -> Sequence[gdb.Breakpoint]:
    return gdb.breakpoints()


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
                 enabled: bool = True,
                 explicit_stop: bool = False,
                 temporary: bool = False):
        super().__init__(bp_str, temporary=temporary)
        if action_funcs is None:
            action_funcs = []
        self._make_unique()
        self._bp_str = bp_str
        self.enabled = enabled
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
        for bp in get_all_breakpoints():
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
