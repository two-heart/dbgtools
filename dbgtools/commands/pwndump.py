import pwndbg
import argparse
import pwndbg.commands
from typing import Optional
from dbgtools.main import get_current_libc_path, wrap_readelf_s, \
                          get_main_arena_off, get_libc_bin_sh


parser = argparse.ArgumentParser(description="Dump useful offsets")
parser.add_argument("--libc", type=str, help="path to libc")
parser.add_argument("--code", action="store_true", help="dump offsets in python syntax")


@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser)
def pwnd(libc: Optional[str] = None, code: bool = False):
    if libc is None:
        libc = get_current_libc_path()

    if libc is None:
        raise ValueError("Couldn't find libc. Specify the path manually!")
    else:
        symbols = ["system", "__free_hook", "__malloc_hook", "malloc",
                   "free", "printf", "dup2", "puts"]
        for sym_name in symbols:
            try:
                sym_addresses = wrap_readelf_s(libc, sym_name)
                if len(sym_addresses) != 0:
                    sym_addr = sym_addresses[0][1]
                    if not code:
                        print(f"{sym_name}: {hex(sym_addr)}")
                    else:
                        print(f"{sym_name}_off = {hex(sym_addr)}")
            except:
                pass
        print()
        main_arena_off = get_main_arena_off(libc)
        if main_arena_off != -1:
            if not code:
                print(f"main_arena_off: {hex(main_arena_off)}")
            else:
                print(f"main_arena_off = {hex(main_arena_off)}")
        else:
            if not code:
                print(f"main_arena_off: Not found")
            else:
                print(f"# main_arena_off: Not found")
        print()
        bin_sh_off = get_libc_bin_sh(libc)
        if not code:
            print(f"/bin/sh: {hex(bin_sh_off)}")
        else:
            print(f"bin_sh_off = {hex(bin_sh_off)}")
