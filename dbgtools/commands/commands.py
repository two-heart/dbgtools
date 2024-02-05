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
from dbgtools.commands.getoffsets import GetOffsetsCmd
from dbgtools.commands.gadgetsearch import GadgetSearchCmd
from dbgtools.commands.asanok import ASANOKCmd
from dbgtools.commands.asanviz import ASANVisualizeCmd
from dbgtools.commands.v8heap import V8HeapCmd



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
GetOffsetsCmd()
GadgetSearchCmd()
ASANOKCmd()
ASANVisualizeCmd()
V8HeapCmd()
