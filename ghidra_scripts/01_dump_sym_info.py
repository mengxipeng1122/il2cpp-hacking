# Ghidra Script to handle vtable in libunity.so
# @category    Unity
# @author      Meng Xipeng
# @keybinding
# @menupath    
# @toolbar     

import re
import json
import socket

import ghidra.app.script.GhidraScript
from ghidra.framework.main import AppInfo
from ghidra.program.model.symbol import SymbolTable, SymbolUtilities, SymbolType

from myghidra import *


# get host name
host_name = socket.gethostname()
print('Host name:{}'.format(host_name))
if host_name == 'LAPTOP-C6D7IK9G':  # Huawei laptop
    temp_dir = 'd:/tt'
else:
    temp_dir = '/tmp'

class UnitySymDumpInfo(ghidra.app.script.GhidraScript):

    def check(self):
        # The script will only work with libunity.so
        current_program_name = currentProgram.getName();
        print("Current program name:{}".format(current_program_name))
        assert current_program_name=='libunity.sym.so', 'This script only can be used with a libunity.sym.*.*.so'

    def run(self):
        self.check()
        # Iterate over all symbols
        infos = {
            'symbols' : getAllSymbols(currentProgram),
        }
        dst_fn = os.path.join(temp_dir,'unity_sym_dump_info.json');
        saveInfoToJsonFile(dst_fn, infos)
        print('Saved to {0} with {1} symbols successfully.'.format(dst_fn, len(infos['symbols'])))

if __name__ == '__main__':
    print("[+] UnitySymDumpInfo ")
    UnitySymDumpInfo().run()
    print("[-] UnitySymDumpInfo ")

