import pwn
import os


# folder this file is in
folder = '/'.join(__file__.split('/')[:-1]) + '/'
p = pwn.gdb.debug(os.path.join(folder, 'bin/basic'), api=True, env=dict())
api = p.gdb
print(api.sys.modules['dbgtools'])
p.sendline(b'A')
