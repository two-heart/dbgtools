import gdb
from dbgtools.main import vmmap


def v8heap_page():
  if not gdb.current_progspace().filename.endswith("d8"):
      print("Failed to detect d8 binary. Output may be wrong")

  # assumption is that v8heap starts at the first writable mapping
  # bricks with ASAN builds :(
  for page in vmmap():
      if page.rw:
          return page

  return None

def v8heap_start_addr():
  if (page := v8heap_page()) is not None:
      return page.start
  else:
      return -1
