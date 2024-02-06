import dbgtools.commands.domalloc
import dbgtools.commands.dofree
import dbgtools.commands.heapbase
import dbgtools.commands.breaknew
import dbgtools.commands.breakpie
import dbgtools.commands.asanok
import dbgtools.commands.asanviz
import dbgtools.commands.v8heap
import dbgtools.commands.gadgetsearch
import dbgtools.commands.libcbase
import dbgtools.commands.traceheap


# TODO(ju256): port the rest of those commands to argparsed commands
from dbgtools.commands.libcsym import LibcSymCmd
from dbgtools.commands.pwndump import PwnDumpCmd
from dbgtools.commands.getoffsets import GetOffsetsCmd

from dbgtools.commands.heaplookup import HeapPtrLookup
from dbgtools.commands.tracer import TracerCmd
from dbgtools.commands.mmap import MmapCmd
from dbgtools.commands.mprotect import MprotectCmd


LibcSymCmd()
PwnDumpCmd()
HeapPtrLookup()
TracerCmd()
MmapCmd()
MprotectCmd()
GetOffsetsCmd()
