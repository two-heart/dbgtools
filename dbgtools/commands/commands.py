from dbgtools.commands.domalloc import DoMallocCmd
from dbgtools.commands.dofree import DoFreeCmd
from dbgtools.commands.libcbase import LibcBaseCmd
from dbgtools.commands.heapbase import HeapBaseCmd
from dbgtools.commands.libcsym import LibcSymCmd
from dbgtools.commands.pwndump import PwnDumpCmd
from dbgtools.commands.traceheap import TraceHeapCmd
from dbgtools.commands.heaplookup import HeapPtrLookup
from dbgtools.commands.tracer import TracerCmd
from dbgtools.commands.breaknew import BreakNewCmd
from dbgtools.commands.breakpie import BreakPIECmd
from dbgtools.commands.mmap import MmapCmd
from dbgtools.commands.mprotect import MprotectCmd



DoMallocCmd()
DoFreeCmd()
LibcBaseCmd()
HeapBaseCmd()
LibcSymCmd()
PwnDumpCmd()
TraceHeapCmd()
HeapPtrLookup()
TracerCmd()
BreakNewCmd()
BreakPIECmd()
MmapCmd()
MprotectCmd()
