import gdb
from dbgtools.main import *


class GetOffsetsCmd(gdb.Command):
    """Retrieves offsets for list of libc symbols for a remote and a local libc"""
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
        if libc_path == "":
                libc_path = self._ask_libc_path(local)
                if libc_path == "":
                    raise ValueError("No path provided!")

        if os.path.exists(libc_path):
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

    def invoke(self, args, from_tty):
        args = args.split()
        if len(args) < 1:
            self.help()
        else:
            symbols = args
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
