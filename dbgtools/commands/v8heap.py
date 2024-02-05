import gdb
from dbgtools.v8 import v8heap_page, v8heap_start_addr
from dbgtools.commands.utils import parse_tint



class V8HeapCmd(gdb.Command):
  """Show V8 heap address"""
  def __init__(self):
    super(V8HeapCmd, self).__init__("v8heap", gdb.COMMAND_USER)

  def help(self):
    print("v8heap (ptr|offset)")

  def invoke(self, args, from_tty):
    args = args.split()
    if len(args) >= 2:
      self.help()
      return
    else:
      v8_heap_page_obj = v8heap_page()
      v8_heap_addr = v8heap_start_addr()
      if v8_heap_addr == -1:
        print("V8 heap not found")
        return
      else:
        if len(args) == 0:
            print(f"V8 heap @ {hex(v8_heap_addr)}")
        else:
          ptr_or_offset = parse_tint(args[0])
          is_offset = ptr_or_offset <= 0xffffffff
          if is_offset:
            offset = ptr_or_offset
            print(f"V8 heap+{hex(offset)} @ {hex(v8_heap_addr+offset)}")
          else:
            ptr = ptr_or_offset
            if ptr >= v8_heap_page_obj.end:
              print("ptr does not seem to be on V8 heap")
            else:
              print(f"V8 heap offset @ {hex(ptr - v8_heap_addr)}")
