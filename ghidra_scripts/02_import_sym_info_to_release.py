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
from ghidra.program.model.symbol import SymbolTable, SymbolUtilities, SymbolType, SourceType

from myghidra import *

# get host name
host_name = socket.gethostname()
print('Host name:{}'.format(host_name))
if host_name == 'LAPTOP-C6D7IK9G':  # Huawei laptop
    temp_dir = 'd:/tt'
else:
    temp_dir = '/tmp'


class UnityImportSymInfo(ghidra.app.script.GhidraScript):

    def check(self):
        # The script will only work with libunity.so
        current_program_name = currentProgram.getName();
        # Get the current program in the code browser
        project_file_name = currentProgram.getDomainFile().getName()
        print('Project file name: ',project_file_name)
        assert project_file_name=='libunity.so_release', 'This script only can be used with a libunity.so_release'

    def run(self):
        self.check()
        # Iterate over all symbols
        fn = os.path.join(temp_dir,'unity_sym_dump_info.json');
        info = json.load(open(fn))
        symbols = info.get('symbols')
        loadSymbols(currentProgram, symbols)

if __name__ == '__main__':
    print("[+] UnityImportSymInfo ")
    UnityImportSymInfo().run()
    print("[-] UnityImportSymInfo ")

