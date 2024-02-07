import gdb
import time
from dbgtools import is_program_running
from dbgtools.gdbapi import run, cont, set_breakpoint, set_watchpoint,\
    delete_all_breakpoints, si, execute_command
from dbgtools.regs import *
from dbgtools.logger import Logger
from dbgtools.commands.utils import parse_tint


class Tracer:
    def __init__(self, trace_end_addr=None, start_bp_addr=None, start_wp_addr=None, force_rerun=True, start_args=None, timeout=60):
        self._trace_end_addr = trace_end_addr
        self._start_bp_addr = start_bp_addr
        self._start_wp_addr = start_wp_addr
        self._force_rerun = force_rerun
        self._start_args = start_args
        self._timeout = timeout
        self._start_time = None

        if self._start_bp_addr is None and self._start_wp_addr is None:
            raise ValueError("Tracer needs atleast start breakpoint or start watchpoint")

    @classmethod
    def get_from_watchpoint(cls, wp_addr, trace_end_addr=None, force_rerun=True, start_args=None, timeout=60):
        return Tracer(start_wp_addr=wp_addr, trace_end_addr=trace_end_addr, force_rerun=force_rerun, start_args=start_args, timeout=timeout)

    @classmethod
    def get_from_breakpoint(cls, bp_addr, trace_end_addr=None, force_rerun=True, start_args=None, timeout=60):
        return Tracer(start_bp_addr=bp_addr, trace_end_addr=trace_end_addr, force_rerun=force_rerun, start_args=start_args, timeout=timeout)

    def start(self):
        if self._start_bp_addr is not None:
            set_breakpoint(self._start_bp_addr)
        elif self._start_wp_addr is not None:
            set_watchpoint(self._start_wp_addr)

        self._start_time = time.time()
        if self._force_rerun:
            run(self._start_args)
        else:
            if is_program_running():
                cont()
            else:
                run(self._start_args)

        # wait for breakpoint or watchpoint hit
        logger = Logger()
        logger.clear_log_file()
        while True:
            try:
                time_ran = (time.time() - self._start_time)
                if time_ran >= self._timeout:
                    print("[Tracer] Hit timeout")
                    break
                # TODO(liam) check if may be null
                log = gdb.execute("x/i $rip", to_string=True)
                if log is None:
                    log = "<unknown>"
                log = log.encode().lstrip(b"=> ").rstrip()
                if len(log) != 0:
                    logger.log_line(b"[Tracer] " + log)
                if self._trace_end_addr is not None and registers.rip == self._trace_end_addr:
                    break
                si()
                # TODO(ju256): use this again if possible
                # dont remember when this broke
                # execute_command("s")
            except gdb.error:
                break

        logger.print_log()
        logger.write_log_to_log_file()


class TracerCmd(gdb.Command):
    """Traces instructions"""
    def __init__(self):
        super(TracerCmd, self).__init__("tracer", gdb.COMMAND_USER)

    def help(self):
        print("Usage: tracer w|b <watchpoint/breakpoint address> <trace end address>")

    def invoke(self, argument, from_tty):
        argument = argument.split()
        if len(argument) < 2:
            self.help()
        else:
            mode = argument[0]
            if mode != "w" and mode != "b":
                self.help()
            else:
                paddr = parse_tint(argument[1])
                if len(argument) == 3:
                    trace_end_addr = parse_tint(argument[2])
                else:
                    trace_end_addr = None
                delete_all_breakpoints()
                if mode == "w":
                    t = Tracer.get_from_watchpoint(paddr, trace_end_addr=trace_end_addr)
                else:
                    t = Tracer.get_from_breakpoint(paddr, trace_end_addr=trace_end_addr)
                t.start()
