import gdb


def is_program_running():
    # very hacky
    try:
        gdb.execute("x $ax", to_string=True)
        return True
    except gdb.error:
        return False
