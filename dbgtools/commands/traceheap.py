from enum import Enum
from typing import Optional
import gdb
import pwndbg
import argparse
import pwndbg.commands
from dbgtools.breakpoints import LogBreakpoint
from dbgtools.main import get_malloc_addr, get_free_addr
from dbgtools.regs import *
from dbgtools.memory import read_stack
from dbgtools.logger import Logger
from dbgtools.utils import singleton


@singleton
class TraceHeapWrapper:
    def __init__(self):
        self._tracing_active: bool = False
        self._trace_bps: list[LogBreakpoint] = []
        self._last_malloc_size: int = -1
        self._cur_tmp_malloc_finish_bp: Optional[LogBreakpoint] = None

    def enable(self):
        if not self._tracing_active:
            self._tracing_active = True
            self._make_bps()
            print("TraceHeap on")

    def disable(self):
        if self._tracing_active:
            for bp in self._trace_bps:
                bp.delete()
                self._trace_bps.remove(bp)
            self._tracing_active = False
            print("TraceHeap off")

    def _make_bps(self):
        for bp in self._trace_bps:
            bp.delete()
            self._trace_bps.remove(bp)
        malloc_addr = get_malloc_addr()
        free_addr = get_free_addr()

        if malloc_addr is None:
            raise ValueError("Address of malloc could not be determined")
        if free_addr is None:
            raise ValueError("Address of free could not be determined")

        free_bp = LogBreakpoint.create_pt_bp(free_addr, self._free_log_func)
        malloc_bp = LogBreakpoint.create_pt_bp(malloc_addr, lambda: "", action_funcs=[self._set_tmp_malloc_bp])
        self._trace_bps = [malloc_bp, free_bp]

    def _set_tmp_malloc_bp(self):
        self._last_malloc_size = registers.rdi
        ret_addr = read_stack()
        self._cur_tmp_malloc_finish_bp = LogBreakpoint.create_pt_bp(ret_addr, self._malloc_log_func, temporary=True)

    def _malloc_log_func(self):
        if self._last_malloc_size == -1 \
           or self._cur_tmp_malloc_finish_bp is None:
            raise ValueError("HeapTracing failed")

        log = f"[TraceHeap] malloc({hex(self._last_malloc_size)}) => {hex(registers.rax)}".encode()
        self._last_malloc_size = -1
        self._cur_tmp_malloc_finish_bp = None
        return log

    def _free_log_func(self) -> str:
        return f"[TraceHeap] free({hex(registers.rdi)})".encode()



class TraceHeapState(Enum):
    ON = "on"
    OFF = "off"
    SHOW_TRACE = ""

    def __str__(self):
        return self.value


parser = argparse.ArgumentParser(description="Traces malloc() and free() calls")
parser.add_argument("state", type=TraceHeapState, nargs='?', choices=list(TraceHeapState), help="on/off state")

@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser)
def traceheap(state: Optional[str] = None):
    if state is None:
        state = TraceHeapState.SHOW_TRACE

    tracewrapper = TraceHeapWrapper()
    if state == TraceHeapState.ON:
        tracewrapper.enable()
    elif state == TraceHeapState.OFF:
        tracewrapper.disable()
    else:
        heap_trace_log = list(filter(lambda l: l.startswith(b"[TraceHeap] "), Logger().content.splitlines()))
        for l in heap_trace_log:
            print(l.replace(b"[TraceHeap] ", b""))
