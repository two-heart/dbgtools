import gdb
from dbgtools.main import get_first_heap_address, get_first_heap_end_address, read_pointer, get_libc_base, get_binary_base
import pwndbg
from dbgtools.commands.utils import parse_tint


class HeapPtrLookup(gdb.Command):
    """Tries to find interesting pointers on the heap"""
    def __init__(self):
        super(HeapPtrLookup, self).__init__("heaplookup", gdb.COMMAND_USER)


    def help(self):
        print("Usage: heaplookup <start address> <end address>")

    def invoke(self, argument, from_tty):     
        argument = argument.split()
        heap_start_addr = get_first_heap_address()
        heap_end_addr = get_first_heap_end_address()
        if heap_start_addr is None or heap_end_addr is None:
            print("Heap start or end address could not be found")
        else:
            if len(argument) == 1:
                start_addr = parse_tint(argument[0])
                end_addr = heap_end_addr
            elif len(argument) == 2:
                start_addr = parse_tint(argument[0])
                end_addr = parse_tint(argument[1])
            elif len(argument) == 0:
                start_addr = heap_start_addr
                end_addr = heap_end_addr
            else:
                self.help()
                return
            if start_addr < heap_start_addr or start_addr > heap_end_addr or end_addr < heap_start_addr or end_addr > heap_end_addr:
                print("Start or end address out of range")
            all_ptrs = []
            for heap_addr in range(start_addr, end_addr, 8):
                ptr = read_pointer(heap_addr)
                page_of_ptr = pwndbg.gdblib.vmmap.find(ptr)
                if page_of_ptr is not None:
                    # TODO(liam) this switching is almost certainly not correct
                    # Therefore: check and refecotor it
                    is_libc_ptr = "libc" in page_of_ptr.objfile
                    is_heap_ptr = ptr in range(heap_start_addr, heap_end_addr)
                    is_stack_ptr = "stack" in page_of_ptr.objfile
                    base_img = ""
                    base_img_off = -1
                    sym_name = pwndbg.gdblib.symbol.get(ptr)

                    progspace = gdb.current_progspace()
                    is_binimg_ptr = False
                    if progspace is not None:
                        is_binimg_ptr = progspace.filename in page_of_ptr.objfile
                    if is_libc_ptr:
                        libc_base = get_libc_base()
                        base_img = "libc"
                        base_img_off = ptr - libc_base
                    elif is_heap_ptr:
                        base_img = "heap"
                        base_img_off = ptr - heap_start_addr
                    elif is_stack_ptr:
                        base_img = "stack"
                        base_img_off = ptr - page_of_ptr.start
                    elif is_binimg_ptr:
                        base_img = "binary"
                        base_img_off = ptr - get_binary_base()
                    self._print(heap_addr, heap_addr - heap_start_addr, ptr, base_img, base_img_off, sym_name, page_of_ptr.execute)

                    all_ptrs.append((heap_addr, heap_addr - heap_start_addr, ptr, base_img, base_img_off, sym_name, page_of_ptr.execute))
            self._print_interesting_ptrs(all_ptrs)

    def _print(self, heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable):
        fstr = f"[{hex(heap_addr)}|heap+{hex(heap_off)}]:\t {hex(ptr)}" 
        if base_img != "":
            fstr += f" | {base_img}+{hex(base_img_off)}"
        if sym_name != "":
            fstr += f" | {sym_name}"
        if points_to_executable:
            fstr += f" (Points to executable memory | Possible function pointer)"
        print(fstr)

    def _print_interesting_ptrs(self, ptr_tpls):
        # heap_addr, heap_off, ptr, base_img, base_img_off, sym_name = ptr_tpls[0]
        # 
        print("="*100)
        print("Libc pointers")
        for heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable in ptr_tpls:
            if base_img == "libc":
                self._print(heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable)
        print()
        print("Binary pointers")
        for heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable in ptr_tpls:
            if base_img == "binary":
                self._print(heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable)
        print()
        print("Stack pointers")
        for heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable in ptr_tpls:
            if base_img == "stack":
                self._print(heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable)
        print()
        print("Possible function pointers")
        for heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable in ptr_tpls:
            if points_to_executable:
                self._print(heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable)
        print("="*100)
