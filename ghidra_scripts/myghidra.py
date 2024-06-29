

# from elftools.elf.elffile import ELFFile
import sys
import os
import shutil
import json
import inspect

# Import the necessary Ghidra classes
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import CategoryPath, DataTypeConflictHandler, DataTypeManager, StructureDataType
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.symbol import Namespace, SymbolTable, SymbolUtilities, SymbolType, SourceType
from ghidra.util.exception import DuplicateNameException, InvalidInputException
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.flatapi import FlatProgramAPI 
from ghidra.app.util.demangler import DemanglerUtil, DemangledObject

import ghidra.app.util.opinion


def isBytesAllZeros(bs):
    all_zero = True
    for b in bs:
        if b != 0:
            return False;
    return True

def showElf(elf):
    print('getByteProvider'                                  , elf.getByteProvider()                               );
    print('getClass'                                         , elf.getClass()                                      );
    print('getDynamicLibraryNames'                           , elf.getDynamicLibraryNames()                        );
    print('getDynamicStringTable'                            , elf.getDynamicStringTable()                         );
    print('getDynamicSymbolTable'                            , elf.getDynamicSymbolTable()                         );
    print('getDynamicTable'                                  , elf.getDynamicTable()                               );
    # print('getDynamicType'                                   , elf.getDynamicType()                                );
    print('getEntryComponentOrdinal'                         , elf.getEntryComponentOrdinal()                      );
    print('getFlags'                                         , elf.getFlags()                                      );
    print('getImageBase'                                     , elf.getImageBase()                                  );
    print('getLoadAdapter'                                   , elf.getLoadAdapter()                                );
    print('getMachineName'                                   , elf.getMachineName()                                );
    print('getPhoffComponentOrdinal'                         , elf.getPhoffComponentOrdinal()                      );
    # print('getProgramHeaderAt'                               , elf.getProgramHeaderAt()                            );
    print('getProgramHeaderCount'                            , elf.getProgramHeaderCount()                         );
    print('getProgramHeaderProgramHeader'                    , elf.getProgramHeaderProgramHeader()                 );
    # print('getProgramHeaderType'                             , elf.getProgramHeaderType()                          );
    # print('getProgramHeaders'                                , elf.getProgramHeaders()                             );
    # print('getProgramLoadHeaderContaining'                   , elf.getProgramLoadHeaderContaining()                );
    # print('getProgramLoadHeaderContainingFileOffset'         , elf.getProgramLoadHeaderContainingFileOffset()      );
    print('getReader'                                        , elf.getReader()                                     );
    # print('getRelocationTable'                               , elf.getRelocationTable()                            );
    # print('getRelocationTableAtOffset'                       , elf.getRelocationTableAtOffset()                    );
    print('getRelocationTables'                              , elf.getRelocationTables()                           );
    # print('getSection'                                       , elf.getSection()                                    );
    # print('getSectionAt'                                     , elf.getSectionAt()                                  );
    # print('getSectionHeaderContainingFileRange'              , elf.getSectionHeaderContainingFileRange()           );
    print('getSectionHeaderCount'                            , elf.getSectionHeaderCount()                         );
    print('getSectionHeaderType'                             , elf.getSectionHeaderType()                          );
    print('getSectionIndex'                                  , elf.getSectionIndex()                               );
    print('getSectionLoadHeaderContaining'                   , elf.getSectionLoadHeaderContaining()                );
    print('getSections'                                      , elf.getSections()                                   );
    print('getShoffComponentOrdinal'                         , elf.getShoffComponentOrdinal()                      );
    print('getStringTable'                                   , elf.getStringTable()                                );
    print('getStringTables'                                  , elf.getStringTables()                               );
    print('getSymbolTable'                                   , elf.getSymbolTable()                                );
    print('getSymbolTables'                                  , elf.getSymbolTables()                               );

def getDataTypeByName(dtm, name):
    rets=  []
    for dt in dtm.getDataTypes(dtm.getLocalSourceArchive()):
        if dt.name == name:
            rets.append(dt)
    if len(rets) == 0 : return None
    if len(rets) == 1 : return rets[0]
    return rets
    
def setFuncByDatatype(func, dt, program):
    # set name
    sourceType = ghidra.program.model.symbol.SourceType.USER_DEFINED
    func.setName(dt.name, sourceType)
    # set returnType
    func.setReturnType(dt.returnType, sourceType )
    # set parameters
    parameterCount = func.getParameterCount()
    for t in range(parameterCount):
        idx = parameterCount-1-t;
        func.removeParameter(idx)
    parameterCount = len(dt.arguments)
    for t in range(parameterCount):
        arg = dt.arguments[t]
        parameter = ghidra.program.model.listing.ParameterImpl(arg.name, arg.dataType,program)
        func.addParameter(parameter, sourceType)

def showInput(i):
    print(' getAddress        ', i. getAddress        ());
    print(' getClass          ', i. getClass          ());
    print(' getDef            ', i. getDef            ());
    print(' getDescendants    ', i. getDescendants    ());
    print(' getHigh           ', i. getHigh           ());
    print(' getLoneDescend    ', i. getLoneDescend    ());
    print(' getMergeGroup     ', i. getMergeGroup     ());
    print(' getOffset         ', i. getOffset         ());
    print(' getPCAddress      ', i. getPCAddress      ());
    print(' getSize           ', i. getSize           ());
    print(' getSpace          ', i. getSpace          ());
    print(' getUniqueId       ', i. getUniqueId       ());
    print(' getWordOffset     ', i. getWordOffset     ());
    print(' isAddrTied        ', i. isAddrTied        ());
    print(' isAddress         ', i. isAddress         ());
    print(' isConstant        ', i. isConstant        ());
    print(' isFree            ', i. isFree            ());
    print(' isHash            ', i. isHash            ());
    print(' isInput           ', i. isInput           ());
    print(' isPersistent      ', i. isPersistent      ());
    print(' isRegister        ', i. isRegister        ());
    print(' isUnaffected      ', i. isUnaffected      ());
    print(' isUnique          ', i. isUnique          ());

def showArg(arg):
    print('getAddress      ', arg.getAddress      ())
    print('getClass        ', arg.getClass        ())
    print('getDef          ', arg.getDef          ())
    print('getDescendants  ', arg.getDescendants  ())
    print('getHigh         ', arg.getHigh         ())
    print('getLoneDescend  ', arg.getLoneDescend  ())
    print('getMergeGroup   ', arg.getMergeGroup   ())
    print('getOffset       ', arg.getOffset       ())
    print('getPCAddress    ', arg.getPCAddress    ())
    print('getSize         ', arg.getSize         ())
    print('getSpace        ', arg.getSpace        ())
    print('getUniqueId     ', arg.getUniqueId     ())
    print('getWordOffset   ', arg.getWordOffset   ())
    print('isAddrTied      ', arg.isAddrTied      ())
    print('isAddress       ', arg.isAddress       ())
    print('isConstant      ', arg.isConstant      ())
    print('isFree          ', arg.isFree          ())
    print('isHash          ', arg.isHash          ())
    print('isInput         ', arg.isInput         ())
    print('isPersistent    ', arg.isPersistent    ())
    print('isRegister      ', arg.isRegister      ())
    print('isUnaffected    ', arg.isUnaffected    ())
    print('isUnique        ', arg.isUnique        ())

def getArgumentsOnReference(currentProgram, fm, reference, ):
    monitor = ConsoleTaskMonitor()
    options = DecompileOptions()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(currentProgram)
    caller = fm.getFunctionContaining(reference.fromAddress)
    if caller:
        res = ifc.decompileFunction(caller, 60, monitor)
        high_func = res.getHighFunction()
        if high_func:
            opiter = high_func.getPcodeOps()
            while opiter.hasNext():
                op = opiter.next()
                mnemonic = str(op.getMnemonic())
                if mnemonic == "CALL":
                    inputs = op.getInputs()
                    addr = inputs[0].getAddress()
                    args = inputs[1:] # List of VarnodeAST types
                    if addr == reference.toAddress:
                        print("Call to {} at {} has {} arguments: {}".format(addr, op.getSeqnum().getTarget(), len(args), args))
                        return  [arg.getDef().inputs[-1].getOffset() for arg in args]

def getStr(bs):
    bs = bytearray([b for b in bs])
    bs = bs.split(b'\0')[0]
    bs = bs.decode('utf-8')
    return bs


def inspect_instance(instance):
    # Get the class name
    class_name = instance.__class__.__name__
    print("Class Name:", class_name)

    # Get all instance attributes
    attributes = inspect.getmembers(instance, lambda a: not(inspect.isroutine(a)))

    # Iterate through the attributes and print field names and values
    for attr_name, attr_value in attributes:
        print("Field ", attr_name, ":", attr_value)
        print("----------")

def inspect_functions(instance):
    # Get the class name
    class_name = instance.__class__.__name__
    print("Class Name:", class_name)
    # Get all methods of the instance
    methods = inspect.getmembers(instance, inspect.ismethod)

    # Iterate through the methods and print their names
    function_names = []
    for method_name, method in methods:
        function_names.append(method_name)
        print("Function Name:", method_name)

    return function_names

def inspect_functions_with_no_arguments(instance):
    # Get all methods of the instance
    methods = inspect.getmembers(instance, inspect.ismethod)

    # Iterate through the methods and print the names of functions with no arguments
    for method_name, method in methods:
        parameters = inspect.signature(method).parameters
        if len(parameters) == 1:  # Exclude 'self' parameter
            print("Function with no arguments:", method_name)

def findFunctionDefinitionsByName(dtm, funcName):
    functionDefinitions = []
    for fundef in dtm.getAllFunctionDefinitions(): 
        if fundef.getName()==funcName:
            functionDefinitions.append(fundef)
    return functionDefinitions
    
def handleAllImportFuncs(mem):
    for b in mem.getBlocks():
        if b.getName() == '.plt':
            print(b, b.getStart(), b.getEnd())
            addressSet = AddressSet(b.getStart(), b.getEnd())
            for func in fm .getFunctions(addressSet, True):
                funcName = func.getName();
                functionDefinitions = findFunctionDefinitionsByName(dtm, funcName)
                funcAddr = func.getEntryPoint();
                if len(functionDefinitions)<1:
                    print(func, func.getEntryPoint(), '', func.getName(), func.getSignature(), functionDefinitions)
                # for reference  in getReferencesTo(funcAddr): print('  =>  ', reference)


def handleAllJNIFunctions():
    inspect_functions(fm)
    monitor = ConsoleTaskMonitor()
    options = DecompileOptions()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(currentProgram)
    for func in fm.getFunctions(True):
        funcName = func.getName()
        funcAddr = func.getEntryPoint()
        if funcName.startswith('Java_'):
            parameterCount = func.getParameterCount();
            if parameterCount<=0:
                print(func)
                res = ifc.decompileFunction(func, 60, monitor)
                high_func = res.getHighFunction()
                if high_func:
                    ghidra.program.model.pcode.HighFunctionDBUtil.commitParamsToDatabase(high_func, False, ghidra.program.model.symbol.SourceType.DEFAULT)
                    print('commited')
            if parameterCount>0:
                parameter = func.getParameter(0)
                print(func, funcAddr, '', func.signature, func.getParameterCount())
                dataType = dtm.getDataType('/jni-ghidra.h/JNIEnv *')
                print(dataType, parameter, parameterCount)
                parameter.setDataType(dataType,  ghidra.program.model.symbol.SourceType.USER_DEFINED )
                parameter.setName('env', ghidra.program.model.symbol.SourceType.USER_DEFINED )
            if parameterCount>1:
                parameter = func.getParameter(1)
                print(func, funcAddr, '', func.signature, func.getParameterCount())
                dataType = dtm.getDataType('/jni-ghidra.h/jobject')
                print(dataType, parameter, parameterCount)
                parameter.setDataType(dataType,  ghidra.program.model.symbol.SourceType.USER_DEFINED )
                parameter.setName('obj', ghidra.program.model.symbol.SourceType.USER_DEFINED )

def handleClassSize(currentProgram, fm,  rm, dtm, mallocAddr, max_trial=10):
    allClassSizes = {}
    allFunctionNeedToCheck = set()
    func = fm.getFunctionAt(mallocAddr)
    funcAddr = func.getEntryPoint()
    referenceTos = rm.getReferencesTo(funcAddr)
    for referenceIdx , reference  in enumerate(referenceTos):
        func = fm.getFunctionContaining(reference.fromAddress)
        if func:
            allFunctionNeedToCheck.add(func)

    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.openProgram(currentProgram)
    for funcIdx, func in enumerate(list(allFunctionNeedToCheck)):
        sz = None
        constructor = None
        res = ifc.decompileFunction(func,180,None)
        high_func = res.getHighFunction()
        if high_func:
            for opIdx, op in  enumerate(list(high_func.getPcodeOps())):
                mnemonic = str(op.getMnemonic())
                if mnemonic == "CALL":
                    inputs = op.getInputs()
                    addr = inputs[0].getAddress()
                    args = inputs[1:] # List of VarnodeAST types
                    targetAddr = addr
                    #print(opIdx,  op, targetAddr, '', mallocAddr)
                    if targetAddr.equals(mallocAddr):
                        inputs = op.getInputs()
                        addr = inputs[0].getAddress()
                        args = inputs[1:] # List of VarnodeAST types
                        sz =  args[0].offset
                        continue
                    if sz!=None:
                        currFunc = fm.getFunctionAt(targetAddr)
                        currFuncName = str(currFunc.getName())
                        currFuncNamespace = str(currFunc.getParentNamespace().getName())
                        if currFuncNamespace != 'Global':
                            # print(' =>', currFunc, currFuncName, currFunc.getParentNamespace().getName())
                            if currFuncName == currFuncNamespace:
                                constructor = currFunc
                                break
        if sz!=None and constructor!=None:
            print(sz, constructor, func)
            allClassSizes[constructor.getName()] = sz
    for clz, sz in allClassSizes.items():
        if sz % 4 == 0:
            dataType = getDataTypeByName(dtm, clz)
            if dataType and dataType.isZeroLength():
                print(clz, sz, hex(sz))
                childDataType = dtm.getDataType('/int')
                for o in range(0, sz, 4):
                    dataType.insert(0, childDataType, -1, None, None)
    

def getFunctionInfo(function):
    fn_entry_point = function.getEntryPoint()
    fn_instructions = function.getProgram().getListing().getInstructions(
        function.getBody(), True)

    # If thumb function, align entry point to 2
    if fn_entry_point.getOffset() % 2 == 1:
      fn_entry_point = fn_entry_point.subtract(1)

    # Iterate over every instruction in the function
    instructionInfos = []
    for instruction in fn_instructions:
      instructionInfos.append({
          'offset': instruction.getAddress().getOffset() - fn_entry_point.getOffset(),
          'mnemonic': instruction.getMnemonicString(),
          'operands': [str(op) for op in instruction.getInputObjects()],
      })
    return {
        'name': function.getName(),
        'entry_point': str(function.getEntryPoint()),
        'instructions': instructionInfos,
    }


def compare_functions(func_info1, func_info2, include_operands=False):
    if include_operands:
        # Extract the instruction mnemonics and operands from the function information
        instructions1 = set([str(instr['mnemonic']) + ' ' + ' '.join(instr['operands']) for instr in func_info1['instructions']])
        instructions2 = set([str(instr['mnemonic']) + ' ' + ' '.join(instr['operands']) for instr in func_info2['instructions']])
    else:
        # Extract only the instruction mnemonics from the function information
        instructions1 = set([instr['mnemonic'] for instr in func_info1['instructions']])
        instructions2 = set([instr['mnemonic'] for instr in func_info2['instructions']])

    # Calculate the intersection and the union of the two instruction sets
    intersection = instructions1.intersection(instructions2)
    union = instructions1.union(instructions2)

    # Calculate the Jaccard index
    jaccard_index = float(len(intersection)) / len(union)

    return jaccard_index


def saveInfoToJsonFile(fn, info):
    # type: (str, dict) -> None
    """
    Saves function information to a JSON file.

    Args:
        fn: Destination file name.
        info: Function information to save.

    Returns:
        None
    """
    # Backup the destinate file if it already exists
    if os.path.isfile(fn):
        dst_bak_fn = fn + '.bak'
        print('Backing up', fn, 'to', dst_bak_fn)
        shutil.copyfile(fn, dst_bak_fn)
    # Save the function information to a JSON file
    with open(fn, 'w') as f:
        json.dump(info, f, indent=2)


# Function to create or get a namespace by its path (e.g., "Namespace1::Namespace2::Namespace3")
def create_or_get_namespace(program, namespace_path):
    symbolTable = program.getSymbolTable()
    currentNamespace = program.getGlobalNamespace()
    
    # Split the namespace path by "::" to handle multi-level namespaces
    namespace_parts = namespace_path.split("::")

    # if the first part is empty, remove it
    if len(namespace_parts)>0 and namespace_parts[0]=='': del namespace_parts[0]
    
    for part in namespace_parts:
        # Check if the namespace part exists in the current namespace
        nextNamespace = symbolTable.getNamespace(part, currentNamespace)
        
        # If the namespace does not exist, create it
        if nextNamespace is None:
            nextNamespace = symbolTable.createNameSpace(currentNamespace, part, SourceType.USER_DEFINED)
        
        # Set the current namespace to the one we just found or created
        currentNamespace = nextNamespace
    
    return currentNamespace

def get_class_namespace_by_name(program,name):
    nameLastPart = name.split('::')[-1]
    symbolTable = program.getSymbolTable()
    for ns in symbolTable.getClassNamespaces():
        ns_name = ns.getName()
        if ns_name == nameLastPart:
            return ns


def align_address(program, address, alignment=4):
    return FlatProgramAPI(program).toAddr(address.getOffset() - (address.getOffset() % alignment))

def read_address(program, address):
    data = FlatProgramAPI(program).getDataAt(address)
    if data and data.isPointer():
        return data.getValue();
    return None
    #raise Exception('Can not to read address at {}'.format(address))

def getProgramPointerSize(program):
    pointer_size = 4
    langId = program.getLanguageID().toString()
    # print('current language: {}'.format(langId))
    if langId == 'AARCH64:LE:64:v8A':
        pointer_size=8
    elif langId == 'ARM:LE:32:v8':
        pointer_size=4
    else:
        raise Exception('Unhandled langID {}'.format(langId))
    return pointer_size

def get_vtab(program, address):
    max_functions = 10000
    pointer_size = getProgramPointerSize(program)
    aligned_address = align_address(program,address,pointer_size)
    ptr=read_address(program,aligned_address)

    if ptr:
        align_address_value = aligned_address.getOffset();
        # try to  find header
        for t in range(max_functions):
            try:
                ptr = FlatProgramAPI(program).toAddr(align_address_value - t*pointer_size);
                addr = read_address(program,ptr)
                # Get the memory block that contains this address
                memoryBlock = program.getMemory().getBlock(addr)
                #print('[*] ptr: {}, addr: {} (section: {})'.format(ptr, addr, memoryBlock.getName()))
                if memoryBlock is None: break;
                if memoryBlock.getName() != '.text': break
            except Exception as e:
                message = str(e)
                if message.startswith('Can not to read address at'):
                    break;
                else:
                    print('Exception ocurred: {}'.format(e))
                    raise e

        vtab_header_value = align_address_value - (t-1)*(pointer_size)
        vtab_header = FlatProgramAPI(program).toAddr(vtab_header_value)
        for t in range(max_functions):
            try:
                ptr = FlatProgramAPI(program).toAddr(vtab_header_value + t*pointer_size);
                addr = read_address(program,ptr)
                # Get the memory block that contains this address
                memoryBlock = program.getMemory().getBlock(addr)
                #print('[*] ptr: {}, addr: {} (section: {})'.format(ptr, addr, memoryBlock.getName()))
                if memoryBlock is None: break;
                if memoryBlock.getName() != '.text': break;
            except Exception as e:
                message = str(e)
                if message.startswith('Can not to read address at'):
                    break;
                else:
                    print('Exception ocurred: {}'.format(e))
                    raise e

        vtab_function_count = t

        return vtab_header, vtab_function_count

def restore_vtab(program, vtab, count):
    """Fix vtable at vtab with count functions"""
    vtab_value = vtab.getOffset()
    pointer_size = getProgramPointerSize(program)
    symbolTable = program.getSymbolTable()
    functionManager = program.getFunctionManager()

    for t in range(count):
        """Fix function at index t in vtable"""
        ptr = FlatProgramAPI(program).toAddr(vtab_value + t*pointer_size)
        func_addr = read_address(program,ptr)
        func_addr_value = func_addr.getOffset()
        func = functionManager.getFunctionAt(func_addr)
        symbol = symbolTable.getPrimarySymbol(func_addr)
        symbol_name = None
        if symbol:
            symbol_name = symbol.getName()

            if not symbol_name.startswith('_ZN'):  # Not mangled
                continue

            if (func_addr_value & 1 == 1) and symbol_name.endswith('+1'):
                symbol_name = symbol_name[:-2]

            func_name = symbol_name
            demangled_name = DemanglerUtil.demangle(program, symbol_name)
            if demangled_name is not None:
                print('demangled name :{}'.format(demangled_name))
                full_namespace_path = demangled_name.getNamespace().toString()
                func_name = demangled_name.getName()
                print("Demangled Name: {},  Namespace path: {},".format(func_name, full_namespace_path))
                namespace = create_or_get_namespace(program, full_namespace_path)
                print('Namespace created or found: {}'.format(namespace.getName()))
                if namespace:
                    clz = symbolTable.convertNamespaceToClass(namespace)
                    print('Class created or found: {}'.format(clz.getName()))
                aligned_func_addr = align_address(program, func_addr, 2)
                func = program.getFunctionManager().getFunctionAt(aligned_func_addr)
                comment = '''
{}
{}
This function is at vtab {} with index {}
                        '''.format(symbol_name, demangled_name.getSignature(), vtab, t)

                if func:
                    if func.getName() != func_name:
                        print('Function at {} already exists with name {}'.format(aligned_func_addr, func.getName()))

                        func.setComment(comment)
                        func.setCallingConvention('__thiscall')
                        func.setName(func_name, SourceType.USER_DEFINED)
                        clz_name = namespace.getName()
                        #if isinstance(clz_name, unicode):
                        #    clz_name = clz_name.encode('ascii', 'ignore')
                        
                        clz_namespace = get_class_namespace_by_name(program,clz_name)
                        if clz_namespace:
                            func.setParentNamespace(clz_namespace)
                else:
                    print('Function at {} not found'.format(aligned_func_addr))
                    func = FlatProgramAPI(program).createFunction(aligned_func_addr, func_name)
                    if func:
                        func.setComment(comment)
                        func.setCallingConvention('__thiscall')
                        func.setName(func_name, SourceType.USER_DEFINED)
                        # func.setParentNamespace(namespace)
                        print('[*] Created a fuction at {} with name {}'.format(aligned_func_addr, func_name))

def getAllSymbols(program):
    """
    Get all symbols (functions) in the given program.

    The returned dictionary has the symbol's address (as a string in hex) as the key,
    and a dictionary with the symbol name and its type as the value.
    """
    symbols = {}
    all_symbols = program.getSymbolTable().getAllSymbols(True)
    for symbol in all_symbols:
        # check if the symbol is a function and its entrypoint
        if symbol.getSymbolType() == SymbolType.LABEL:
            address = symbol.getAddress()
            key = hex(int(address.getOffset()))
            name = symbol.getName()
            if program.getFunctionManager().getFunctionContaining(address):
                # Print the label name and its address
                symbols[key] = {'name': name, 'type': 'function'}
                continue
            symbols[key] = {'name': name, 'type': 'label'}
    

    return symbols


def loadSymbols(program, symbols):
    """
    Load symbols to the given program

    symbols is a dictionary, where the key is the address of the symbol (as a string in hex),
    and the value is a dictionary with the symbol name and its type.
    """
    symbolTable = program.getSymbolTable()
    functionManager = program.getFunctionManager()
    for k, v in symbols.items():
        address = FlatProgramAPI(program).toAddr(int(k, 0))
        name = v.get('name')
        if name:
            # Set a symbol at specified address, and with name
            symbol = symbolTable.getPrimarySymbol(address)
            if symbol == None or symbol.getName() != name:
                print('[*] Create symbol at {} with name {}'.format(hex(address.getOffset()), name))
                symbol = symbolTable.createLabel(address, name, SourceType.IMPORTED)
                symbol_type = v.get('type')
                if symbol_type:
                    if symbol_type == 'function':
                        func = functionManager.getFunctionAt(address)
                        if not func:
                            # create function in case it doesn't exists
                            func = FlatProgramAPI(program).createFunction(address, name)
                        else:
                            try:
                                func.setName(name, SourceType.USER_DEFINED)
                            except ghidra.util.exception.DuplicateNameException:
                                pass

def get_all_vtabs(program):
    symbolTable = program.getSymbolTable()

    memory_block_name = '.data.rel.ro'
    data_rel_memory_block=None
    pointer_size = getProgramPointerSize(program)
    # Iterate through all memory blocks
    for block in program.getMemory().getBlocks():
        # Get the starting address of the block
        start_address = block.getStart()
        # Get the ending address of the block
        end_address = block.getEnd()
        if block.getName() == memory_block_name:
            # Iterate through all addresses in the block
            print('[*] Checking block {} {} - {}'.format(
                block.getName(),
                hex(start_address.getOffset()), 
                hex(end_address.getOffset()),
            ))
            data_rel_memory_block = block;

    start_address = data_rel_memory_block.getStart()
    # Get the ending address of the block
    end_address = data_rel_memory_block.getEnd()

    all_vtabs = []
    curr_address = start_address
    while curr_address < end_address:
        # check 
        bs = FlatProgramAPI(program).getBytes(curr_address, pointer_size*2)
        if isBytesAllZeros(bs):
            # print('found p0 p0 {} {}'.format( curr_address, bs))
            curr_address = curr_address.add(pointer_size*2)
            is_vtab = False
            try:
                p = read_address(program, curr_address)
                if p:
                    func = program.getFunctionManager().getFunctionAt(p)
                    if func:
                        print('Found function {} at {}'.format(func, p))
                        is_vtab = True
                        #return
            except Exception as e:
                message = str(e)
                if message.startswith('Can not to read address at'):
                    continue
                else:
                    raise e

            if is_vtab:
                vtab = get_vtab(program, curr_address)
                if vtab:
                    vtab_address, n = vtab
                    print('[*] Found vtab at {} with count {}'.format(vtab_address, n))
                    curr_address = vtab_address.add(pointer_size*n)
                    all_vtabs.append(vtab)
                    continue
            
        curr_address=curr_address.add(pointer_size);
    return all_vtabs;


def get_all_vtabs_for_dump(program):

    memory_block_name = '.data.rel.ro'
    data_rel_memory_block=None
    pointer_size = getProgramPointerSize(program)
    # Iterate through all memory blocks
    for block in program.getMemory().getBlocks():
        # Get the starting address of the block
        start_address = block.getStart()
        # Get the ending address of the block
        end_address = block.getEnd()
        if block.getName() == memory_block_name:
            # Iterate through all addresses in the block
            print('[*] Checking block {} {} - {}'.format(
                block.getName(),
                hex(start_address.getOffset()), 
                hex(end_address.getOffset()),
            ))
            data_rel_memory_block = block;

    start_address = data_rel_memory_block.getStart()
    # Get the ending address of the block
    end_address = data_rel_memory_block.getEnd()

    all_vtabs = []
    curr_address = start_address
    while curr_address < end_address:
        # check 
        bs = FlatProgramAPI(program).getBytes(curr_address, pointer_size*2)
        if isBytesAllZeros(bs):
            # print('found p0 p0 {} {}'.format( curr_address, bs))
            curr_address = curr_address.add(pointer_size*2)
            is_vtab = False
            try:
                p = read_address(program, curr_address)
                if p:
                    pass
                    # check the 
                    memoryBlock = program.getMemory().getBlock(p)
                    if memoryBlock and memoryBlock.getName() == '.text':
                        is_vtab = True
                        #return
            except Exception as e:
                message = str(e)
                if message.startswith('Can not to read address at'):
                    continue
                else:
                    raise e

            if is_vtab:
                vtab = get_vtab(program, curr_address)
                if vtab:
                    vtab_address, n = vtab
                    print('[*] Found vtab at {} with count {}'.format(vtab_address, n))
                    curr_address = vtab_address.add(pointer_size*n)
                    all_vtabs.append(vtab)
                    continue
            
        curr_address=curr_address.add(pointer_size);
    return all_vtabs;


def get_vtab_info(program, vtab_address, vtab_count):
    symbolTable = program.getSymbolTable();
    pointer_size =  getProgramPointerSize(program)

    print('Vtable adderss : {}'.format(vtab_address))
    vtab_name = None
    if not vtab_name:
        symbol = FlatProgramAPI(program).getSymbolAt(vtab_address)
        if symbol:
            vtab_name = symbol.getName(True)

    items = []

    for t in range(vtab_count):
        address = vtab_address.add(t*pointer_size);
        target_address=read_address(program,address)
        item_name = None
        symbol = FlatProgramAPI(program).getSymbolAt(target_address)
        func_address = align_address(program,target_address,2)
        func =  FlatProgramAPI(program).getFunctionAt(func_address)
        if not item_name:
            item_name = symbol.getName()
        func_comment = func.getComment()
        if func_comment:
            func_comment_lines = func_comment.splitlines()
            item_name = func_comment_lines[0] if func_comment_lines[0] else func_comment_lines[1]
            item_name = item_name.strip()

        assert item_name, 'Item name must not be empty'
        fixed_item_name = item_name[:-2]  if(item_name.endswith('+1')) else  item_name
        print("Item # {} addreess {} label {}  function {} {} {}".format(t, address, item_name, func, func_address, fixed_item_name))
        items.append({
            'name' : fixed_item_name,
        }) 

    return {
        'name' : vtab_name,
        'address' : hex(vtab_address.getOffset()),
        'count' : vtab_count,
        'items': items,
    }


def fix_vtab(program, vtab_address, vtab_count):
    symbolTable = program.getSymbolTable();
    pointer_size =  getProgramPointerSize(program)

    print('Vtable adderss : {}'.format(vtab_address))
    vtab_name = None
    if not vtab_name:
        symbol = FlatProgramAPI(program).getSymbolAt(vtab_address)
        if symbol:
            vtab_name = symbol.getName(True)

    for t in range(vtab_count):
        address = vtab_address.add(t*pointer_size);
        target_address=read_address(program,address)
        item_name = None
        symbol = FlatProgramAPI(program).getSymbolAt(target_address)
        func_address = align_address(program,target_address,2)
        func =  FlatProgramAPI(program).getFunctionAt(func_address)
        if not func:
            FlatProgramAPI(program).createFunction(func_address, None)

        print("Item # {} addreess {} label {}  function {} {} ".format(t, address, symbol, func, func_address))



def import_info_to_vtab(program, info, vtab_address, vtab_count):   
    info_count =  info['count']
    pointer_size = getProgramPointerSize(program)

    assert info_count == vtab_count, 'Count missmatch {}/{}'.format(vtab_count, info_count)

    for t in range(vtab_count):
        address = vtab_address.add(t*pointer_size)
        target_address = read_address(program, address)
        func_address = align_address(program, target_address, 2)
        func =  FlatProgramAPI(program).getFunctionAt(func_address)
        assert func, 'Need to create a function at {}'.format(func_address)

        info_func_name = info['items'][t]['name']
        func.setName(info_func_name, SourceType.USER_DEFINED)
    

def isThumbFunction(program,func):
    r = program.getRegister("TMode")
    value = program.programContext.getRegisterValue(r, func.entryPoint)
    return value.unsignedValueIgnoreMask == 1


