import dbgtools
from dbgtools.regs import *


dbgtools.CustomBreakpoint('*(vuln+349)', explicit_stop=True)
dbgtools.gdbapi.run()

assert dbgtools.asan.access_ok(registers.rax)
assert not dbgtools.asan.access_ok(registers.rax + 0x100)

dbgtools.asan.visualize_region(registers.rax + 0xd0)
