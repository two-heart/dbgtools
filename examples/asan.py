import dbgtools
from dbgtools.regs import *


dbgtools.CustomBreakpoint('*(vuln+349)', explicit_stop=True)
dbgtools.gdb_run()

assert dbgtools.asan.asan_ok(registers.rax)
assert not dbgtools.asan.asan_ok(registers.rax + 0x100)

dbgtools.asan.asan_visualize_region(registers.rax + 0xd0)
