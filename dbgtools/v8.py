import gdb
from dbgtools.main import vmmap
from dbgtools.memory import read_u64


HEAP_BASE_TO_SELF_OFF = 0x20


# TODO(ju256): only works in d8. expand this to properly find the v8 heap base in
# renderer processes of chrome
def v8heap_page():
  if not gdb.current_progspace().filename.endswith("d8"):
      print("Failed to detect d8 binary. Output may be wrong")

  for page in vmmap():
      if page.rw and read_u64(page.start+HEAP_BASE_TO_SELF_OFF) & (~0xffff) == page.start:
          return page.start

  return None

def v8heap_start_addr():
  if (page := v8heap_page()) is not None:
      return page.start
  else:
      return -1
