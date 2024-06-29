#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set ts=4 sts=4 sw=4 expandtab:


# This script generates a json file that contains information about all the functions
# in the binary. It uses the Ghidra Decompiler to get the function bodies.
#

import sys
import os
import json
import re
import glob

from myghidra import *


dump_dir = "/tmp/fundumps/"

class IndexFunctionInUnity(ghidra.app.script.GhidraScript):
    def check(self):
        # The script will only work with libunity.so
        current_program_name = currentProgram.getName();
        # Get the current program in the code browser
        project_file_name = currentProgram.getDomainFile().getName()
        assert project_file_name=='libunity.so', 'This script only can be used with a libunity.so_release'
    def indexFunc(self, function, dump_dir):
        fun_info = getFunctionInfo(function)
        files = glob.glob(dump_dir + '/*.json')
        matches = [(json.load(open(f)), compare_functions(fun_info, json.load(open(f))))
                   for f in files]
        max_match = max(matches, key=lambda x: x[1])
        if max_match[1] == 1.0:
            name = max_match[0]['name']
            print('  set name {} {}'.format(name, max_match[1]))
            function.setName(name, SourceType.USER_DEFINED)

    def indexFunctions(self,dump_dir):
        functionManager = currentProgram.getFunctionManager();
        f = functionManager.getFunctionContaining(currentAddress)
        if f is not None:
            # Print source type of the function
            print('Source type: {}'.format(f.getSymbol().getSource().name))
            print('The current address is contained in function: {}'.format(f.getName()))
            self.indexFunc(f, dump_dir)
        else:
            print('The current address is not contained in a function')
            answer = self.askYesNo("Do you want to continue, it will be very slow?")
            if not answer:
                return

            # List all functions in current program
            print('Listing functions in program:')
            functions = current_program.getFunctionManager().getFunctions(True)
            for f in functions:
                # Skip external and thunk functions
                if f is not None:
                    print('Source type: {}'.format(f.getSymbol().getSource().name))
                    # if f.getSymbol().getSource() != SourceType.USER_DEFINED: continue
                    print('  {}'.format(f.getName()))
                    self.indexFunc(f, dump_dir)

    def run(self):
        self.check()
        self.indexFunctions(dump_dir)


if __name__ == '__main__':
    print("[+] IndexFunctionInUnity")
    if not os.path.exists(dump_dir):
        os.makedirs(dump_dir)
    IndexFunctionInUnity().run()
    print("[-] IndexFunctionInUnity")



