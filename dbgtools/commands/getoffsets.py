import pwndbg
import argparse
import pwndbg.commands
import os.path
from typing import Optional
from dbgtools.main import get_current_libc_path, resolve_symbol_address



def build_python_offsets_code(local_libc_symbols_with_address, binary_symbols_with_address):
    data = ""
    for sym_name, address in binary_symbols_with_address:
        addr_str = hex(address) if address != -1 else -1
        sym_str = sym_name.replace("@got", "_got").replace("@plt", "_plt")
        data += f"{sym_str}_off = {addr_str}\n"
    data += "\n"

    for sym_name, address in local_libc_symbols_with_address:
        addr_str = hex(address) if address != -1 else -1
        data += f"{sym_name}_off = {addr_str}\n"

    return data


parser = argparse.ArgumentParser(description="Retrieves offsets for list of (libc|binary) symbols")
parser.add_argument("symbols", nargs='+', type=str, default=[], help="symbols to resolve")
parser.add_argument("--libc", type=str, help="path to libc")
# TODO(ju256): --code flag? probably useless but might consider


@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(parser)
def get_offsets(symbols: list[str], libc: Optional[str] = None):
    if libc is not None:
        if not os.path.exists(libc_path):
            raise ValueError(f"Libc not found at given path {libc_path}!")
    else:
        libc = get_current_libc_path()

        libc_symbols_with_address = []
        # TODO(ju256): kinda shit. we might want libc@(got|plt) support as well + non got plt binary offsets?
        libc_symbols = list(filter(lambda s: not (s.endswith("@plt") or s.endswith("@got")), symbols))
        binary_symbols = list(filter(lambda s: s not in libc_symbols, symbols))

        for sym_name in libc_symbols:
            sym_addr = resolve_symbol_address(sym_name, libc)
            libc_symbols_with_address.append((sym_name, sym_addr))

        binary_symbols_with_address = [(sym, resolve_symbol_address(sym)) for sym in binary_symbols]
        print(build_python_offsets_code(libc_symbols_with_address, binary_symbols_with_address))
