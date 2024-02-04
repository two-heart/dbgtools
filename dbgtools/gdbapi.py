import gdb


def execute_commands(cmds):
    for cmd in cmds:
        gdb.execute(cmd, to_string=True)
