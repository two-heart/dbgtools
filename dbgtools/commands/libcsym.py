import gdb
from dbgtools.main import get_current_libc_path, wrap_readelf_s, \
                        get_libc_base, get_function_symbol_addr

# TODO(liam) too much logic in a command
def _resolve_symbol_address(sym_name: str, libc_path: str,
                           current_libc_used: bool) -> None:

    sym_addresses = wrap_readelf_s(libc_path, sym_name)
    if len(sym_addresses) == 1:
        print(f"{sym_name}: {hex(sym_addresses[0][1])}")
    elif len(sym_addresses) == 0 and current_libc_used:
        clibc_base = get_libc_base()
        clibc_sym_addr = get_function_symbol_addr(sym_name)
        if clibc_base is None or clibc_sym_addr is None:
            print(f"{sym_name}: Not found")
        else:
            print(f"{sym_name}: {hex(clibc_sym_addr - clibc_base)}")
    else:
        if len(sym_addresses) == 0:
            print(f"{sym_name}: Not found")
        else:
            print(f"{sym_name}: ")
            for sa in sym_addresses:
                print(f"\t{sa[0]}: {hex(sa[1])}")

class LibcSymCmd(gdb.Command):
    """Lookup of libc symbols"""
    def __init__(self):
        super(LibcSymCmd, self).__init__("libcsym", gdb.COMMAND_USER)

    def invoke(self, argument, from_tty):
        argument = argument.split()
        current_libc_used = False
        if "--path" in argument:
            libc_path = argument[argument.index("--path") + 1]
            argument = argument[:argument.index("--path")] \
                       + argument[argument.index("--path")+2:]
        else:
            libc_path = get_current_libc_path()
            current_libc_used = True
        if "--code" in argument:
            argument = argument[:argument.index("--code")] \
                       + argument[argument.index("--code")+1:]
        
        if libc_path is None:
            print("Couldn't find libc. Specify the path manually!")
            return
        else:
            print(f"Using {libc_path}")
            if len(argument) == 0:
                symbols = ["system", "__free_hook", "__malloc_hook", "malloc",
                           "free", "printf", "dup2"]
            else:
                symbols = argument
            for sym_name in symbols:
                try:
                    _resolve_symbol_address(libc_path, sym_name,
                                           current_libc_used)
                except ValueError:
                    print(f"{sym_name}: ", "not found")


    def help(self):
        print("Usage: libcsym [<symbol name>, <symbol name>, ...] [--path <path>]")


# TODO(liam) merge with libcsym command?
"""
class GetOffsetsCmd(gdb.Command):
    \"\"\"Retrieves offsets for list of libc symbols for a remote and a local libc\"\"\"
    def __init__(self):
        super(GetOffsetsCmd, self).__init__("get_offsets", gdb.COMMAND_USER)

    def help(self):
        print("Usage: get_offsets <space separated symbol list>")

    def _ask_libc_path(local):
        if local:
            print("System libc could not be found!")
        else:
            print("Remote libc could not be found!")
        print("Please provide a path manually")
        path = input("Path: ").strip()

    def _get_libc_path(self, local):
        if local:
            libc_path = get_system_libc_path()
            if libc_path == "":
                libc_path = get_current_libc_path()
        else:
            try:
                libc_path = search_libc_in_dir()[0]
            except IndexError:
                libc_path = ""
        if libc_path == "" or libc_path is None:
                libc_path = self._ask_libc_path(local)
                if libc_path == "":
                    raise ValueError("No path provided!")

        if libc_path is not None and os.path.exists(libc_path):
            return libc_path
        else:
            raise ValueError(f"Libc not found at given path {libc_path}!")

    def _build_python_offsets_code(self, local_libc_symbols_with_address, remote_libc_symbols_with_address, binary_symbols_with_address):
        data = ""
        data += f"LOCAL = True\n\n"
        for sym_name, address in binary_symbols_with_address:
            addr_str = hex(address) if address != -1 else -1
            sym_str = sym_name.replace("@got", "_got").replace("@plt", "_plt")
            data += f"{sym_str}_off = {addr_str}\n"
        data += "\n"

        data += "if LOCAL: \n"
        for sym_name, address in local_libc_symbols_with_address:
            addr_str = hex(address) if address != -1 else -1
            data += f"    {sym_name}_off = {addr_str}\n"

        data += "else: \n"
        for sym_name, address in remote_libc_symbols_with_address:
            addr_str = hex(address) if address != -1 else -1
            data += f"    {sym_name}_off = {addr_str}\n"
        return data

    def invoke(self, argument, from_tty):
        argument = argument.split()
        if len(argument) < 1:
            self.help()
        else:
            symbols = argument
            # get path for local and 'remote' libc
            try:
                local_libc_path = self._get_libc_path(local=True)
                remote_libc_path = self._get_libc_path(local=False)
            except ValueError as e:
                print("Error during libc path lookup!")
                print(str(e))
                return

            print(f"Using local path = {local_libc_path} | remote path = {remote_libc_path}")
            local_libc_symbols_with_address = []
            remote_libc_symbols_with_address = []
            libc_symbols = list(filter(lambda s: not (s.endswith("@plt") or s.endswith("@got")), symbols))
            binary_symbols = list(filter(lambda s: s not in libc_symbols, symbols))

            for sym in libc_symbols:
                local_address = resolve_symbol_address(sym, local_libc_path)
                remote_address = resolve_symbol_address(sym, remote_libc_path)
                local_libc_symbols_with_address.append((sym, local_address))
                remote_libc_symbols_with_address.append((sym, remote_address))

            binary_symbols_with_address = [(sym, resolve_symbol_address(sym)) for sym in binary_symbols]
            print(self._build_python_offsets_code(local_libc_symbols_with_address, remote_libc_symbols_with_address, binary_symbols_with_address))
"""
