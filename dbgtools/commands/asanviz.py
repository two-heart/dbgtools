import gdb
from dbgtools.asan import asan_visualize_region
from dbgtools.commands.utils import parse_tint


class ASANVisualizeCmd(gdb.Command):
  """Visualize asan redzones"""
  def __init__(self):
    super(ASANVisualizeCmd, self).__init__("asanviz", gdb.COMMAND_USER)

  def help(self):
    print("asanviz <ptr>")

  def invoke(self, args, from_tty):
    args = args.split()
    if len(args) != 1:
      self.help()
      return
    else:
      ptr = parse_tint(args[0])
      asan_visualize_region(ptr)
