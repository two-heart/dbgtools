from dbgtools.logger import Logger
from dbgtools.gdbapi import execute_commands
from dbgtools.gdbapi import run, cont
import re

logger = Logger()
execute_commands(["tb *main", "tb *main+92"])

run()

execute_commands(["traceheap on"])

cont()

execute_commands(["traceheap off"])

heap_trace_log = list(filter(lambda l: l.startswith(b"[TraceHeap] "), Logger().content.splitlines()))
heap_trace_log = [l.decode().lstrip("[TraceHeap] ") for l in heap_trace_log]

mallocs = []
frees = []

for l in heap_trace_log:
    if (m := re.match(r"malloc\((0x[a-f0-9]+)\) => (0x[a-f0-9]+)", l)):
        mallocs.append(m.groups())
    if (m := re.match(r"free\((0x[a-f0-9]+)\)", l)):
        frees.append(m.groups())

malloc_sizes = [int(m[0], 16) for m in mallocs]
malloc_ptrs = [int(m[1], 16) for m in mallocs]
free_ptrs = [int(m[0], 16) for m in frees]

assert malloc_sizes == [0x80, 0x20, 0x1000]
assert set(malloc_ptrs) == set(free_ptrs)

