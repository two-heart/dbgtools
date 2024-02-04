import gdb
from dbgtools.main import get_current_libc_path, wrap_readelf_s, \
                          get_main_arena_off, get_libc_bin_sh

class PwnDumpCmd(gdb.Command):
    """Dump useful offsets"""
    def __init__(self):
        super(PwnDumpCmd, self).__init__("pwnd", gdb.COMMAND_USER)

    def invoke(self, argument, from_tty):
        argument = argument.split()
        libc_path = None
        if "--path" in argument:
            libc_path = argument[argument.index("--path") + 1]
            argument = argument[:argument.index("--path")] \
                       + argument[argument.index("--path")+2:]
        else:
            libc_path = ""
        if "--code" in argument:
            argument = argument[:argument.index("--code")] \
                       + argument[argument.index("--code")+1:]
        
        if libc_path == "":
            libc_path = get_current_libc_path()

        if libc_path is None:
            print("Couldn't find libc. Specify the path manually!")
        else:
            if len(argument) == 0:
                symbols = ["system", "__free_hook", "__malloc_hook", "malloc",
                           "free", "printf", "dup2", "puts"]
                for sym_name in symbols:
                    try:
                        sym_addresses = wrap_readelf_s(libc_path, sym_name)
                        if len(sym_addresses) != 0:
                            print(f"{sym_name}: {hex(sym_addresses[0][1])}")
                    except:
                        pass
                print()
                main_arena_off = get_main_arena_off(libc_path)
                if main_arena_off != -1:
                    print(f"main_arena_off: {hex(main_arena_off)}")
                else:
                    print(f"main_arena_off: Not found")
                print()
                bin_sh_off = get_libc_bin_sh(libc_path)
                print(f"/bin/sh: {hex(bin_sh_off)}")
            else:
                self.help()

    def help(self):
        print("Usage: pwnd [--path <path>] [--code]")
