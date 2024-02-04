from dbgtools.gdbapi import execute_commands


def supress_output():
    execute_commands(["set logging file /dev/null",
                      "set logging redirect on",
                      "set logging enabled on",
                      "set context-output /dev/null"])


def reenable_output():
    execute_commands(["set logging redirect off",
                      "set logging enabled off",
                      "set context-output stdout"])

class SupressedOutput():
    def __enter__(self):
        supress_output()
      
    def __exit__(self, exc_type, exc_value, exc_traceback):
        reenable_output()


def parse_tint(s):
    if "0x" in s:
        return int(s, 16)
    else:
        return int(s)
