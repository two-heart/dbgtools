import gdb
import pwndbg
import argparse
import pwndbg.commands
from typing import Optional
from dbgtools.main import get_first_heap_address, get_first_heap_end_address, get_libc_base, get_binary_base, ptr_to_symbol
from dbgtools.memory import read_pointer


def print_interesting(heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable):
        fstr = f"[{hex(heap_addr)}|heap+{hex(heap_off)}]:\t {hex(ptr)}"
        if base_img != "":
            fstr += f" | {base_img}+{hex(base_img_off)}"
        if sym_name != "":
            fstr += f" | {sym_name}"
        if points_to_executable:
            fstr += f" (Points to executable memory | Possible function pointer)"
        print(fstr)

def print_summary(ptr_tpls):
    # heap_addr, heap_off, ptr, base_img, base_img_off, sym_name = ptr_tpls[0]
    print("="*100)
    print("Libc pointers")
    for heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable in ptr_tpls:
        if base_img == "libc":
            print_interesting(heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable)
    print()
    print("Binary pointers")
    for heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable in ptr_tpls:
        if base_img == "binary":
            print_interesting(heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable)
    print()
    print("Stack pointers")
    for heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable in ptr_tpls:
        if base_img == "stack":
            print_interesting(heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable)
    print()
    print("Possible function pointers")
    for heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable in ptr_tpls:
        if points_to_executable:
            print_interesting(heap_addr, heap_off, ptr, base_img, base_img_off, sym_name, points_to_executable)
    print("="*100)


parser = argparse.ArgumentParser(description="Tries to find interesting pointers on the heap")
parser.add_argument("--start", type=int, help="pointer to start scanning from")
parser.add_argument("--end", type=int, help="pointer to stop scanning on")


@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser)
def heaplookup(start: Optional[int] = None, end: Optional[int] = None):
    heap_start_addr = get_first_heap_address()
    heap_end_addr = get_first_heap_end_address()
    if heap_start_addr is None or heap_end_addr is None:
        raise ValueError("Heap start or end address could not be found")

    if start is None:
        start = heap_start_addr
    if end is None:
        end = heap_end_addr

    if start < heap_start_addr or start > heap_end_addr or end < heap_start_addr or end > heap_end_addr:
        print("Start or end address out of range")
    all_ptrs = []
    for heap_addr in range(start, end, 8):
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
            sym_name = ptr_to_symbol(ptr)

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
            print_interesting(heap_addr, heap_addr - heap_start_addr, ptr, base_img, base_img_off, sym_name, page_of_ptr.execute)

            all_ptrs.append((heap_addr, heap_addr - heap_start_addr, ptr, base_img, base_img_off, sym_name, page_of_ptr.execute))
    print_summary(all_ptrs)
