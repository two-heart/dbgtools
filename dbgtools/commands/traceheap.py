import gdb
from dbgtools.breakpoints import LogBreakpoint
from dbgtools.main import get_malloc_addr, get_free_addr
from dbgtools.regs import *
from dbgtools.memory import read_stack
from dbgtools.logger import Logger


class TraceHeapCmd(gdb.Command):
    """Traces malloc() and free() calls"""
    def __init__(self):
        self._tracing_active = False
        self._trace_bps = []
        self._cur_tmp_malloc_finish_bp = None
        self._last_malloc_size = -1
        super(TraceHeapCmd, self).__init__("traceheap", gdb.COMMAND_USER)

    def _make_bps(self):
        for bp in self._trace_bps:
            bp.delete()
            self._trace_bps.remove(bp)
        malloc_addr = get_malloc_addr()
        free_addr = get_free_addr()

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

        log = f"[TraceHeap] malloc({hex(self._last_malloc_size)}) => {hex(registers.rax)}"
        self._last_malloc_size = -1
        self._cur_tmp_malloc_finish_bp = None
        return log

    def _free_log_func(self) -> str:
        return f"[TraceHeap] free({hex(registers.rdi)})"

    def invoke(self, argument, from_tty):
        argument = argument.split()
        if len(argument) == 1:
            if argument[0] == "on":
                self._tracing_active = True
                self._make_bps()
                print("TraceHeap on")
            elif argument[0] == "off":
                for bp in self._trace_bps:
                    bp.delete()
                    self._trace_bps.remove(bp)
                self._tracing_active = False
                print("TraceHeap off")
            else:
                self.help()

        elif len(argument) == 0:
            heap_trace_log = list(filter(lambda l: l.startswith(l), Logger.get_instance().content.splitlines()))
            for l in heap_trace_log:
                # TODO(liam) types look sus here
                print(l.replace("[TraceHeap] ", ""))
        else:
            self.help()
                


    def help(self):
        print("Usage: traceheap (<on|off>)")
