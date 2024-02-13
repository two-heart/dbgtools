from typing import Optional, Sequence
import gdb
import re
import pwndbg

def execute_commands(cmds: list[str]) -> Sequence[str]:
    for cmd in cmds:
        yield execute_command(cmd)

def execute_command(cmd: str) -> str:
    return gdb.execute(cmd, to_string=True)

def set_breakpoint(addr: int):
    execute_command(f"b *{hex(addr)}")

def set_watchpoint(addr: int):
    execute_command(f"watch *{hex(addr)}")

def delete_all_breakpoints():
    execute_command("del")

def run(args: Optional[list[str]] = None):
    if args is not None:
        execute_command(f"r {' '.join(args)}")
    else:
        execute_command("r")

# TODO(ju256): dont like
def cont():
    execute_command("c")

def si():
    execute_command("si")

def parse_and_eval(s: str):
    return gdb.parse_and_eval(s)

def finish():
    execute_command("finish")

def examine(ptr: int, repeat: int = 8, size: int = 8, fmt: str = "x"):
    size_fmt_map = {1: 'b', 2: 'h', 4: 'w', 8: 'g'}
    if size not in size_fmt_map.keys():
        raise ValueError(f"size has to be in {list(size_fmt.keys())}")
    size_fmt = size_fmt_map[size]
    data = execute_command(f"x/{repeat}{size_fmt}{fmt} {hex(ptr)}")
    if size == 8:
        # color potential pointers
        matches = re.findall(r"(0x[a-z0-9]{8,16})", data)
        for q in matches:
            colored = pwndbg.color.memory.get(int(q, 16), q)
            data = data.replace(q, colored)
    return data
