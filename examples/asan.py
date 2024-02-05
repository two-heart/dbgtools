import dbgtools
from dbgtools.types import *


dbgtools.CustomBreakpoint('*(vuln+349)', explicit_stop=True)
dbgtools.gdb_run()

assert dbgtools.asan.asan_ok(dbgtools.registers.rax)
assert not dbgtools.asan.asan_ok(dbgtools.registers.rax + 0x100)

dbgtools.asan.asan_visualize_region(dbgtools.registers.rax + 0xd0)
