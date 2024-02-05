### Code is shit and cursed but works
### TODO: refactor


from dbgtools.main import *


from abc import ABC, abstractmethod
from typing import Optional, Union
import types


class FieldPointerType:
  def can_be_derefed(self):
    return False

  def is_pointer_type(self):
    return False


class FieldUserDefinedType:
  @classmethod
  def is_user_defined_type(cls):
    return False


class FieldCallableType:
  @classmethod
  def is_callable(cls):
    return False



class FieldType(ABC, FieldPointerType, FieldUserDefinedType, FieldCallableType):
  FIELD = True
  def __init__(self, size: Optional[int] = None):
    self._size = size
    self._skip_print = False

  def set_skip_print(self):
    self._skip_print = True

  def skip_print(self):
    return self._skip_print

  def size(self) -> int:
    return self._size

  @abstractmethod
  def read(self, ptr: int):
    ...

  @abstractmethod
  def write(self, ptr: int, value):
    ...

  def str(self, ptr: int):
    return str(self.read(ptr))

  def is_initialized(self):
    return True



class U8Type(FieldType):
  def __init__(self):
    super().__init__(1)

  def read(self, ptr: int):
    return read_u8(ptr)

  def write(self, ptr: int, value):
    return write_u8(ptr, value)

  def str(self, ptr: int):
    return hex(self.read(ptr))



class U16Type(FieldType):
  def __init__(self):
    super().__init__(2)

  def read(self, ptr: int):
    return read_u16(ptr)

  def write(self, ptr: int, value):
    return write_u16(ptr, value)

  def str(self, ptr: int):
    return hex(self.read(ptr))


class BoolType(FieldType):
  def __init__(self):
    super().__init__(4)

  def read(self, ptr: int):
    return read_bool(ptr)

  def write(self, ptr: int, value):
    return write_bool(ptr, value)


class S32Type(FieldType):
  def __init__(self):
    super().__init__(4)

  def read(self, ptr: int):
    return read_s32(ptr)

  def write(self, ptr: int, value):
    return write_s32(ptr, value)


class S64Type(FieldType):
  def __init__(self):
    super().__init__(8)

  def read(self, ptr: int):
    return read_s64(ptr)

  def write(self, ptr: int, value):
    return write_s64(ptr, value)


class U32Type(FieldType):
  def __init__(self):
    super().__init__(4)

  def read(self, ptr: int):
    return read_u32(ptr)

  def write(self, ptr: int, value):
    return write_u32(ptr, value)

  def str(self, ptr: int):
    return hex(self.read(ptr))


class U64Type(FieldType):
  def __init__(self):
    super().__init__(8)

  def read(self, ptr: int):
    return read_u64(ptr)

  def write(self, ptr: int, value):
    return write_u64(ptr, value)

  def str(self, ptr: int):
    return hex(self.read(ptr))


class DoubleType(FieldType):
  def __init__(self):
    super().__init__(8)

  def read(self, ptr: int):
    return read_double(ptr)

  def write(self, ptr: int, value):
    return write_double(ptr, value)


class FloatType(FieldType):
  def __init__(self):
    super().__init__(4)

  def read(self, ptr: int):
    return read_float(ptr)

  def write(self, ptr: int, value):
    return write_float(ptr, value)


class StringFieldType(FieldType):
  def __init__(self, length: Optional[int] = None):
    self._length = length
    super().__init__(length)

  def read(self, ptr):
    return read_string(ptr, self._length)

  def write(self, ptr: int, value):
    return write_string(ptr, value, self._length)


class StringTypeMeta(type):
  def __getitem__(cls, args):
    length = args
    return lambda: StringFieldType(length)


class UserDefinedType:
  FIELD = True
  @classmethod
  def is_user_defined_type(cls):
    return True

  def __init__(self, ptr: Optional[int] = None, referenced_user_defined_type_fields: Optional[list["StructFieldInstance"]] = None):
    self._ptr = ptr
    self._skip_print = False

    if referenced_user_defined_type_fields is None:
      referenced_user_defined_type_fields = []
    self._referenced_user_defined_type_fields: list["StructFieldInstance"] = referenced_user_defined_type_fields

  def is_pointer_type(self):
    return False

  def can_be_derefed(self):
    return False

  @classmethod
  def is_callable(cls):
    return False

  def initialize_referenced_ud_type(self):
    for field in self._referenced_user_defined_type_fields:
      field.set_ptr(self.ptr() + field.offset())
      field.initialize_referenced_ud_type()

  def ptr(self):
    if self._ptr is not None:
      return self._ptr
    else:
      raise ValueError("ptr needs to be set")

  def set_ptr(self, ptr: Optional[int]):
    self._ptr = ptr

  def set_skip_print(self):
    self._skip_print = True

  def skip_print(self):
    return self._skip_print

  def is_initialized(self):
    return self._ptr is not None


class StringType(metaclass=StringTypeMeta):
  ...


class IPointer:
  def __init__(self, ref_ptr: int, type: Union[FieldType, UserDefinedType], is_mutable: bool):
    self._ref_ptr = ref_ptr
    self._type = type
    assert self._type.is_pointer_type()
    self._is_mutable = is_mutable

  def __call__(self, *args):
    # allow call directly on pointer for convenience
    if self._type.can_be_derefed():
      sub_type = self._type.deref()
      if sub_type.is_callable():
        icallable = sub_type.gen_ifc()
        return icallable(*args)

    raise TypeError("Only pointers holding callables can be called")

  def __str__(self):
    return f"Pointer[{hex(self._ptr())}]"

  def _mutable(self):
    return self._is_mutable

  def __getattribute__(self, attr):
    if attr == "data":
      return self._data()
    elif attr == "ptr":
      return self._ptr()
    else:
        return object.__getattribute__(self, attr)

  def __setattr__(self, attr, value):
    if attr == "data":
      if not self._mutable():
        raise ValueError("Pointer is not mutable")

      if self._type.can_be_derefed():
        sub_type = self._type.deref()
        if sub_type.is_pointer_type():
          raise ValueError("Pointer data cannot be written directly")
        elif sub_type.is_user_defined_type():
          raise ValueError("User defined types cannot be written directly behind a pointer")
        elif sub_type.is_callable():
          raise ValueError("Callables cannot be written directly behind a pointer")
        else:
          sub_type.write(self._ptr(), value)
      else:
        raise ValueError("Can't deref")
    elif attr == "ptr":
      if not self._mutable():
        raise ValueError("Pointer is not mutable")

      write_pointer(self._ref_ptr, value)
      if self._type.can_be_derefed():
        sub_type = self._type.deref()
        if sub_type.is_pointer_type() or sub_type.is_user_defined_type() or sub_type.is_callable():
          sub_type.set_ptr(value)
    else:
      return object.__setattr__(self, attr, value)

  def _data(self):
    if self._type.can_be_derefed():
      sub_type = self._type.deref()
      if sub_type.is_pointer_type():
        return IPointer(self._ptr(), sub_type, sub_type.mutable())
      elif sub_type.is_user_defined_type():
        return sub_type
      elif sub_type.is_callable():
        return sub_type.gen_ifc()
      else:
        return sub_type.read(self._ptr())
    else:
      raise ValueError("Can't deref")

  def _ptr(self):
    return read_pointer(self._ref_ptr)


class PointerFieldType(FieldType):
  def __init__(self, type: Union[FieldType, UserDefinedType], mutable: bool = False):
    self._type = type
    assert self._type is None or hasattr(self._type, "FIELD")
    super().__init__(8)
    self._ptr = None
    self._mutable = mutable

  def mutable(self):
    return self._mutable

  def set_ptr(self, ptr):
    d = read_pointer(ptr)
    self._ptr = ptr
    if self.can_be_derefed() and (self.is_user_defined_type() or self.is_callable()):
      self._type.set_ptr(d)

  def is_callable(self):
    return self.can_be_derefed() and self._type.is_callable()

  def ptr(self):
    assert self._ptr is not None
    return self._ptr

  def initialize_referenced_ud_type(self):
    if self.is_user_defined_type():
      self._type.initialize_referenced_ud_type()

  def is_pointer_type(self):
    return True

  def can_be_derefed(self):
    return self._type is not None

  def is_user_defined_type(self):
    return self.can_be_derefed() and self._type.is_user_defined_type()

  def read(self):
    raise NotImplementedError()

  def deref(self):
    assert self.can_be_derefed()
    if self._type.is_user_defined_type():
      return self._type
    else:
      return self._type

  def write(self, value):
    raise NotImplementedError()

  def str(self, ptr: int):
    if self.can_be_derefed():
      p = read_pointer(ptr)
      if not self.is_user_defined_type():
        return f"{hex(p)} -> {self._type.str(p)}"
      else:
        sstr = self._type.str(p)
        out = f"{hex(p)} -> \n"
        for l in sstr.splitlines():
          out += " " * 2 + l + "\n"
        return out
    else:
      return hex(read_pointer(self.ptr()))

  def __str__(self):
    return f"Pointer[{hex(self.ptr())}]"


class PointerTypeMeta(type):
  def __getitem__(cls, args):
    if args is not None:
      type = args()
    else:
      type = args
    return lambda: PointerFieldType(type, False)


class PointerType(metaclass=PointerTypeMeta):
  ...


class MutPointerTypeMeta(type):
  def __getitem__(cls, args):
    if args is not None:
      type = args()
    else:
      type = args
    return lambda: PointerFieldType(type, True)


class MutPointerType(metaclass=MutPointerTypeMeta):
  ...


class ArrayFieldType(FieldType):
  def __init__(self, length: int, element_type: FieldType):
    self._length = length
    self._element_type = element_type
    self._element_size = self._element_type.size()
    super().__init__(self._length * self._element_size)

  def read(self, ptr):
    array = []
    for i in range(self._length):
      array.append(self._element_type.read(ptr + (i * self._element_size)))
    return array

  def write(self, ptr: int, value):
    for i in range(self._length):
      self._element_type.write(ptr + (i * self._element_size), value[i])


class ArrayTypeMeta(type):
  def __getitem__(cls, args):
    if len(args) != 2:
      raise ValueError("Expecting element type and length")
    else:
      element_type = args[0]()
      length = args[1]
      return lambda: ArrayFieldType(length, element_type)


class ArrayType(metaclass=ArrayTypeMeta):
  ...


VoidPointerType = PointerType[None]
MutVoidPointerType = MutPointerType[None]



class PaddingFieldType(FieldType):
  def __init__(self, size: int):
    super().__init__(size)

  def skip_print(self):
    return True

  def read(self, ptr: int):
    raise NotImplementedError()

  def write(self, ptr: int, value):
    raise NotImplementedError()

class PaddingTypeMeta(type):
  def __getitem__(cls, size):
    return lambda: PaddingFieldType(size)


class Padding(metaclass=PaddingTypeMeta):
  ...

Gap = Padding


######################



class ArrayMeta(type):
  def __new__(meta, name, bases, attrs):
    if attrs["__qualname__"] != "Array":
      assert "__annotations__" in attrs.keys()
      annotations = attrs["__annotations__"]
      if "length" in annotations.keys():
        length = annotations["length"]
        del annotations["length"]
      else:
        length = None

      assert len(annotations.keys()) == 1
      element_type = list(annotations.values())[0]
      if element_type.is_callable():
        raise ValueError("Callables cannot be the element type of an array. Wrap the callable in a pointer type")

      attrs["element_type"] = element_type()
      attrs["_hidden_length"] = length
      del attrs["__annotations__"]

    return type.__new__(meta, name, bases, attrs)


# FIXME: something still of with array not initializing their element if its a struct
class Array(UserDefinedType, metaclass=ArrayMeta):
  def __init__(self, ptr: Optional[int] = None, length: Optional[int] = None):
    ref_type = None
    pointer_type = None
    callable_type = None
    if self._element_type().is_pointer_type():
      pointer_type = self._element_type()
    elif self._element_type().is_user_defined_type():
      ref_type = self._element_type()
    elif self._element_type().is_callable():
      raise ValueError("Callables cannot be the element type of an array. Wrap the callable in a pointer type")

    ref_types = [ref_type] if ref_type is not None else []
    super().__init__(ptr, ref_types)
    self._length = length

    if self.is_initialized():
      if ref_type is not None:
        ref_type.set_ptr(self.ptr())
      if pointer_type is not None:
        pointer_type.set_ptr(self.ptr())
      if callable_type:
        callable_type.set_ptr(self.ptr())

  def set_length(self, length: int):
    self._length = length

  def _get_hidden_length(self):
    return object.__getattribute__(self, "_hidden_length")

  def length(self):
    if self._length is not None:
      return self._length
    elif self._get_hidden_length() is not None:
      return self._get_hidden_length()
    else:
      raise ValueError("size not specified")

  def _element_type(self):
    return object.__getattribute__(self, "element_type")

  def element_size(self):
    return self._element_type().size()

  def size(self):
    return self.element_size() * self.length()

  def get(self, idx: int):
    element_ptr = self.ptr() + (idx * self.element_size())
    if self._element_type().is_pointer_type():
      field = self._element_type()
      return IPointer(element_ptr, field, field.mutable())
    elif self._element_type().is_user_defined_type():
      field = self._element_type()
      field.set_ptr(element_ptr)
      return field
    elif self._element_type().is_callable():
      assert 0
    else:
      return self._element_type().read(element_ptr)

  def get_str(self, idx: int):
    element_ptr = self.ptr() + (idx * self.element_size())
    if self._element_type().is_pointer_type():
      field = self._element_type()
      return str(IPointer(element_ptr, field, field.mutable()))
    elif self._element_type().is_user_defined_type():
      field = self._element_type()
      field.set_ptr(element_ptr)
      return field.str(element_ptr)
    elif self._element_type().is_callable():
      assert 0
    else:
      return self._element_type().str(element_ptr)


  def set(self, idx: int, value):
    assert not self._element_type().is_user_defined_type() and not self._element_type().is_pointer_type() and not self._element_type().is_callable()
    return self._element_type().write(self.ptr() + (idx * self.element_size()), value)

  def items(self) -> list:
    return list(map(self.get, list(range(self.length()))))

  def str(self, ptr):
    self.set_ptr(ptr)
    if self._element_type().is_user_defined_type():
      field = self._element_type()
      field.set_ptr(ptr)
    return str(self)

  def __str__(self):
    l = list(map(self.get_str, list(range(0, min(self.length(), 20)))))
    if self.length() > 20:
      l.append("...")
    return str(l)

  def __getitem__(self, idx):
    return self.get(idx)

  def __setitem__(self, idx, value):
    return self.set(idx, value)



class ICallable:
  def __init__(self, param_count: int, func_ptr: int):
    self._param_count = param_count
    self._func_ptr = func_ptr

  def str(self, ptr: int):
    return str(self)

  def __str__(self):
    symbol = ptr_to_symbol(self._func_ptr)
    if symbol == "":
      target_str = hex(self._func_ptr)
    else:
      target_str = f"{hex(self._func_ptr)} <{symbol}>"
    return f"Callable({target_str})({', '.join(['_']*self._param_count)})"

  def __call__(self, *args):
    if len(args) != self._param_count:
      raise ValueError(f"Invalid amount of parameters: Expected {self._param_count} got {len(args)}")

    if len(args) > 6:
      raise ValueError("Only supporting registers call arguments for now")

    return call_function(self._func_ptr, *args)


class CallableFieldType(FieldType):
  def __init__(self, param_count: int, func_ptr: Optional[int] = None):
    self._param_count = param_count

    self._func_ptr = func_ptr

  def set_ptr(self, func_ptr: int):
    self._func_ptr = func_ptr

  def ptr(self):
    assert self._func_ptr is not None
    return self._func_ptr

  def gen_ifc(self):
    return ICallable(self._param_count, self.ptr())

  def __str__(self):
    return str(self.gen_ifc())

  def str(self, ptr):
    return str(self)

  def size(self):
    return 0

  def read(self, ptr: int):
    raise NotImplementedError("Callables cannot be read from or written to")

  def write(self, ptr: int):
    raise NotImplementedError("Callables cannot be read from or written to")

  @classmethod
  def is_callable(cls):
    return True


# TODO: implement different calling conventions (or atleast easy interface)
class CallableMeta(type):
  def __getitem__(cls, args):
    param_count = args
    return lambda: CallableFieldType(param_count)



class Callable(metaclass=CallableMeta):
  ...




######################


class StructFieldInstance:
  def __init__(self, offset: int, field: Union[FieldType, UserDefinedType]):
    assert hasattr(field, "FIELD")
    self._offset = offset
    self._field = field

  def mutable(self):
    return self._field.mutable()

  def skip_print(self):
    return self._field.skip_print()

  def set_skip_print(self):
    self._field.set_skip_print()

  def offset(self):
    return self._offset

  def set_offset(self, offset: int):
    self._offset = offset

  def read(self, ptr: int):
    return self._field.read(ptr + self._offset)

  def write(self, ptr: int, value):
    return self._field.write(ptr + self._offset, value)

  def size(self) -> int:
    return self._field.size()

  def str(self, ptr: int) -> str:
    return self._field.str(ptr + self._offset)

  def is_user_defined_type(self) -> bool:
    return self._field.is_user_defined_type()

  def ptr(self) -> int:
    assert self.is_user_defined_type()
    return self._field.ptr()

  def set_ptr(self, ptr: int) -> int:
    assert self.is_user_defined_type() or self.is_pointer_type()
    self._field.set_ptr(ptr)
    if self.is_user_defined_type() or self.is_pointer_type():
      self.initialize_referenced_ud_type()

  def initialize_referenced_ud_type(self):
    assert self.is_user_defined_type() or self.is_pointer_type()
    self._field.initialize_referenced_ud_type()

  def field(self):
    return self._field

  def is_initialized(self):
    return self._field.is_initialized()

  def can_be_derefed(self):
    return self._field.can_be_derefed()

  def is_callable(self):
    raise NotImplementedError("Struct fields should never contain callables directly")

  def deref(self, ptr: int):
    assert self.can_be_derefed()
    return self._field.deref()

  def is_pointer_type(self):
    return self._field.is_pointer_type()



class StructFieldMeta(type):
  def __getitem__(cls, args):
    if type(args) == tuple and len(args) == 2:
      offset = args[0]
      field_type = args[1]
    elif type(args) != tuple:
      offset = None
      field_type = args
    else:
      raise ValueError("Expecting (offset and) field_type")

    field_type = field_type()
    assert hasattr(field_type, "FIELD")
    field = field_type
    return StructFieldInstance(offset, field)


class StructField(metaclass=StructFieldMeta):
  pass



class StructMeta(type):
  def __new__(meta, name, bases, attrs):
    field_names = []
    if attrs["__qualname__"] != "Struct":
      assert "__annotations__" in attrs.keys()
      annotations = attrs["__annotations__"]
      user_defined_types = []
      cur_position = 0

      if "_size" in annotations.keys():
        struct_type_size = annotations["_size"]
        del annotations["_size"]
        attrs["_hidden_type_size"] = struct_type_size

      for field_name in annotations.keys():
          field = annotations[field_name]
          # if field.is_user_defined_type():
          # we need to setup the pointer somehow
          # raise NotImplementedError()
          if not hasattr(field, "_offset"):
            field = StructFieldInstance(cur_position, field())
            cur_position += field.size()
          else:
            assert field.offset() >= cur_position
            cur_position = field.offset()
          if field_name.startswith("_"):
            field.set_skip_print()

          attrs[field_name] = field
          field_names.append(field_name)

      attrs["_field_names"] = field_names
      del attrs["__annotations__"]

    return type.__new__(meta, name, bases, attrs)


class Struct(UserDefinedType, metaclass=StructMeta):
  def __init__(self, ptr: Optional[int] = None):
    ref_types = []
    pointer_types = []
    for field_name in self._field_names:
      field = self._get_raw_field(field_name)
      if field.is_user_defined_type():
        ref_types.append(field)
      elif field.is_pointer_type():
        pointer_types.append(field)

    super().__init__(ptr, ref_types)

    if self.is_initialized():
      for field in ref_types:
        field.set_ptr(self.ptr() + field.offset())

      for field in pointer_types:
        field.set_ptr(self.ptr() + field.offset())

  def str(self, ptr: int):
    return str(self)

  def __str__(self):
    out = ""
    for field_name in self._field_names:
      field = self._get_raw_field(field_name)
      prefix = f"({field_name}) {hex(field.offset())}|"
      if not field.skip_print() and not field.is_user_defined_type():
        out += f"{prefix} {field.str(self.ptr())}\n"
      elif field.is_user_defined_type():
        out += f"{prefix}\n"
        sstr = field.str(self.ptr())
        for l in sstr.splitlines():
          out += (" " * 2) + l + "\n"

    return out

  def _get_raw_field(self, field_name: str):
    return object.__getattribute__(self, field_name)

  def __getattribute__(self, attr):
    if attr == "_field_names":
      return object.__getattribute__(self, attr)
    else:
      if attr in self._field_names:
        field = self._get_raw_field(attr)
        if field.is_pointer_type():
          return IPointer(self.ptr() + field.offset(), field.field(), field.mutable())
        elif field.is_user_defined_type():
          return field.field()
        else:
          return field.read(self.ptr())
      else:
        return object.__getattribute__(self, attr)

  def __setattr__(self, attr, value):
    if attr in self._field_names:
      field = self._get_raw_field(attr)
      assert not field.is_user_defined_type() and not field.is_pointer_type()
      return field.write(self.ptr(), value)
    else:
      return object.__setattr__(self, attr, value)

  def _get_hidden_struct_size(self) -> Optional[int]:
    if hasattr(self, "_hidden_type_size"):
      return object.__getattribute__(self, "_hidden_type_size")
    else:
      return None

  def size(self):
    sz = 0

    hidden_struct_size = self._get_hidden_struct_size()
    if hidden_struct_size is not None:
      sz = hidden_struct_size
    else:
      for field_name in self._field_names:
        sz += self._get_raw_field(field_name).size()
    return sz



class UnionMeta(type):
  def __new__(meta, name, bases, attrs):
    field_names = []
    if attrs["__qualname__"] != "Union":
      assert "__annotations__" in attrs.keys()
      annotations = attrs["__annotations__"]
      user_defined_types = []

      for field_name in annotations.keys():
          field = annotations[field_name]
          field = field()
          attrs[field_name] = field
          field_names.append(field_name)

      attrs["_field_names"] = field_names
      del attrs["__annotations__"]

    return type.__new__(meta, name, bases, attrs)


class Union(UserDefinedType, metaclass=UnionMeta):
  def __init__(self, ptr: Optional[int] = None):
    ref_types = []
    pointer_types = []
    for field_name in self._field_names:
      field = self._get_raw_field(field_name)
      if field.is_user_defined_type():
        ref_types.append(field)
      elif field.is_pointer_type():
        pointer_types.append(field)
      elif field.is_callable():
        raise ValueError("Callables cannot be fields in a struct. Wrap the callable in a pointer type")

    super().__init__(ptr, ref_types)

    if self.is_initialized():
      for field in ref_types + pointer_types:
        field.set_ptr(self.ptr())

  def str(self, ptr: int):
    return str(self)

  def __str__(self):
    out = ""
    for field_name in self._field_names:
      field = self._get_raw_field(field_name)
      prefix = f"{field_name}|"
      assert not field.skip_print()
      if not field.is_user_defined_type():
        out += f"{prefix} {field.str(self.ptr())}\n"
      else:
        assert field.is_user_defined_type()
        out += f"{prefix}\n"
        sstr = field.str(self.ptr())
        for l in sstr.splitlines():
          out += (" " * 2) + l + "\n"

    return out

  def _get_raw_field(self, field_name: str):
    return object.__getattribute__(self, field_name)

  def __getattribute__(self, attr):
    if attr == "_field_names":
      return object.__getattribute__(self, attr)
    else:
      if attr in self._field_names:
        field = self._get_raw_field(attr)
        if field.is_pointer_type():
          return IPointer(self.ptr(), field, field.mutable())
        elif field.is_user_defined_type():
          return field
        elif field.is_callable():
          assert 0
        else:
          return field.read(self.ptr())
      else:
        return object.__getattribute__(self, attr)

  def __setattr__(self, attr, value):
    if attr in self._field_names:
      field = self._get_raw_field(attr)
      assert not field.is_user_defined_type() and not field.is_pointer_type()
      return field.write(self.ptr(), value)
    else:
      return object.__setattr__(self, attr, value)

  def size(self):
    szs = []

    for field_name in self._field_names:
      szs.append(self._get_raw_field(field_name).size())
    return max(szs)




class FunctionPtrMeta(type):
  def __getitem__(cls, args):
    return PointerType[Callable[args]]


class FunctionPtr(metaclass=FunctionPtrMeta):
  pass
