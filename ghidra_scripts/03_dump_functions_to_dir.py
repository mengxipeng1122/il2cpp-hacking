#!/usr/bin/env python
# -*- coding: utf-8 -*-

# vim: set ts=4 sts=4 sw=4 expandtab:

import sys
import os
import json
import re

from myghidra import *


dump_dir = "/tmp/fundumps/"


class DumpFunctionToDir(ghidra.app.script.GhidraScript):
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
        # Get the functions
        functionManager = currentProgram.getFunctionManager()
        functions = functionManager.getFunctions(False)
        dump_functions = [
            func for func in functions
            if not func.isThunk() and not func.getName().startswith(("FUN_", "_INIT_", "_FINT_"))
        ]

        # Iterate over each function and dump its info
        for idx, function in enumerate(dump_functions):
          info_fn = os.path.join(dump_dir, "{:08d}".format(idx) + ".json")
          info = getFunctionInfo(function)
          json.dump(info, open(info_fn, 'w'))
          print('Write to {}'.format(info_fn))


if __name__ == '__main__':
    print("[+] UnityImportSymInfo ")
    if not os.path.exists(dump_dir):
      os.makedirs(dump_dir)
    DumpFunctionToDir().run()
    print("[-] UnityImportSymInfo ")



