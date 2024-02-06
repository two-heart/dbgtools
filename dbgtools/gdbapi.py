from typing import Optional
import gdb


def execute_commands(cmds: list[str]):
    for cmd in cmds:
        gdb.execute(cmd, to_string=True)

def execute_command(cmd: str):
    execute_commands([cmd])

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
