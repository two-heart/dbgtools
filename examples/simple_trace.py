import dbgtools
from dbgtools.logger import Logger


def log() -> bytes:
    return b'hit log breakpoint'
    

dbgtools.LogBreakpoint('*(main+12)', log)
logger = Logger.get_instance()
logger.print_log()
dbgtools.gdb_run()
