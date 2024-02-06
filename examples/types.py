import dbgtools
from dbgtools.types import *
from dbgtools.regs import *


class A(Struct):
  x: U32Type
  y: U32Type


class Test(Struct):
  data: MutPointerType[StringType[None]]
  flt: DoubleType
  b: BoolType
  _: Padding[4]
  a: PointerType[A]
  func_ptr: FunctionPtr[2]


# TODO:
# - add array + union tests
# - pointer arithmetic test
# - explicit offset test



def parse_struct():
    t = Test(registers.rsi)
    print(t)

    assert t.data.data == b'AAAAAAABBBBBBBB\x00'
    assert t.data.ptr != 0
    assert t.flt == 1.1
    assert t.b == True

    a = t.a.data
    assert a.x == 0x1337
    assert a.y == 0x420

    t.func_ptr(0x13, 0x37) == 0x13 * 0x37

    t.data.data = b"XXXXYYYY\x00"
    t.flt = 1337.1337

    a.x = 1234
    assert a.x == 1234
    assert t.a.data.x == 1234



dbgtools.CustomBreakpoint('*(main+169)', explicit_stop=True)
dbgtools.gdbapi.run()


parse_struct()
