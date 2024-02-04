import gdb
from dbgtools.commands.utils import parse_tint
from dbgtools.main import get_heap_base


class HeapBaseCmd(gdb.Command):
    """Looks up the base address of all existing heaps"""
    def __init__(self):
        super(HeapBaseCmd, self).__init__("heapbase", gdb.COMMAND_USER)

    def invoke(self, argument, from_tty):
        argument = argument.split()
        if len(argument) != 1 and len(argument) != 0:
            self.help()
        else:
            heap_addresses = get_heap_base()
            if heap_addresses is None:
                print("no heap found")
            elif len(heap_addresses) == 1 and heap_addresses[0] != -1:
                heap_ptr = heap_addresses[0]
                if len(argument) == 1:
                    ptr = parse_tint(argument[0])
                    print(f"heap @ {hex(heap_ptr)} | off: {hex(ptr - heap_ptr)}")
                else:
                    print(f"heap @ {hex(heap_ptr)}")
            elif len(heap_addresses) >= 2:
                print("Found multiple heaps")
                for hp in heap_addresses:
                    print(f"heap @ {hex(hp)}")
                
    def help(self):
        print("Usage: heapbase [<ptr>]")
