from dbgtools.main import read_byte, read_u64


NORMAL = "\x1b[0m"
RED = "\x1b[31m"
GREEN = "\x1b[32m"
BLUE = "\x1b[34m"


ASAN_REGION_RANGE = 0x50


def asan_ok(ptr):
  return read_byte((ptr >> 3) + 0x7fff8000) == 0

def asan_visualize_region(optr):
  def pad_mem(ptr):
    return "0x" + (hex(read_u64(p1))[2:]).rjust(16, "0")

  def pad_color_asan(ptr):
    v = pad_mem(ptr)
    color = GREEN if asan_ok(ptr) else RED
    return color+v

  for ptr in range(optr - ASAN_REGION_RANGE, optr + ASAN_REGION_RANGE, 16):
    p1 = ptr
    p2 = ptr + 8
    v1 = pad_color_asan(p1)
    v2 = pad_color_asan(p2)

    if p1 == optr:
      pp = f"{BLUE}{hex(p1)}{NORMAL}"
    else:
      pp = hex(p1)

    print(f"{NORMAL}{pp}: {v1}      {v2}{NORMAL}")
