# Ghidra Bufferoverflow Detection
# @category: Bufferoverflow Detection

from ghidra.app.util.XReferenceUtil import *
from ghidra.util.task import *
from ghidra.program.model.util import *
from ghidra.app.decompiler.flatapi import *
from ghidra.program.flatapi import *
from ghidra.app.decompiler import *
from ghidra.program.model.symbol import *
from ghidra.program.database.references import *
from copy import copy
import csv

#Dictionary of known sinks and the arguments we need to find th sources for
Sinks_Args = {
    "strcpy": {'charptr1':'RDI', 'charptr2':'RSI'},
    "strncpy": {'charptr1':'RDI', 'charptr2':'RSI', 'int':'RDX'},
    "strlcpy": {'charptr1':'RDI', 'charptr2':'RSI', 'int':'RDX'},
    "strcat": {'charptr1':'RDI', 'charptr2':'RSI'},
    "strncat": {'charptr1':'RDI', 'charptr2':'RSI', 'int':'RDX'},
    "strlcat": {'charptr1':'RDI', 'charptr2':'RSI', 'int':'RDX'},
    "wcscpy": {'charptr1':'RDI', 'charptr2':'RSI'},
    "wcsncpy": {'charptr1':'RDI', 'charptr2':'RSI', 'int':'RDX'},
    "wcscat": {'charptr1':'RDI', 'charptr2':'RSI'},
    "wcsncat": {'charptr1':'RDI', 'charptr2':'RSI', 'int':'RDX'},
    "memcpy": {'charptr1':'RDI', 'charptr2':'RSI', 'int':'RDX'},
    "memmove": {'charptr1':'RDI', 'charptr2':'RSI', 'int':'RDX'},
    "gets": {'charptr1':'RDI'},
    "fgets": {'charptr1':'RDI', 'int':'RSI'}
}

#Dictionary of String Length functions
String_Length = {
    "strlen": {'arg1':'RDI'},
    "wcslen": {'arg1':'RDI'},
}

#Set of the Registers
Registers = {"RAX","EAX","AX","AL","AH",
            "RBX","EBX","BX","BL","BH",
            "RCX","ECX","CX","CL","CH",
            "RDX","EDX","DX","DL","DH",
            "RDI","EDI","DI","DIL",
            "RSI","ESI","SI","SIL",
            "RBP","EBP","BP","BPL",
            "RSP","ESP","SP","SPL",
            "R8","R8D","R8W","R8B",
            "R9","R9D","R9W","R9B",
            "R10","R10D","R10W","R10B",
            "R11","R11D","R11W","R11B",
            "R12","R12D","R12W","R12B",
            "R13","R13D","R13W","R13B",
            "R14","R14D","R14W","R14B",
            "R15","R15D","R15W","R15B",
            "XMM0","XMM1","XMM2","XMM3","XMM4","XMM5","XMM6","XMM7"}

#Set of Registers used for offset math
TopRegisters = {"RAX","RBX","RCX","RDX","RDI","RSI",
                "R8","R9","R10","R11","R12","R13","R14","R15"}

GlobalSources = []
FunctionsUsed = set([])
FunctionLocals = {}
SecondPass = False
OutputFile = True
FindSourceLimit = 10        #Limites the number of recursive calls
Listing = currentProgram.getListing()
AddressFactory = currentProgram.getAddressFactory()
RefMangager = currentProgram.getReferenceManager()
ProgramName = currentProgram.getName()

MAX_INT = 2147483647
INST_TO = 0                 #Operand1 position with respect to the comma
INST_FROM = 1               #Operand2 position with respect to the comma
REMOVE_INST = 4             #Amount to remove for three letter instructions
REMOVE_4LETTER_INST = 5     #Amount to remove for a four letter instruction
ARGUMENT = 0                #In Find_Source(), position of argument in source list
LOCATION = 1                #In Find_Source(), position of location in source list
INSTRUCTION = 2             #In Find_Source(), position of instruction in source list   
OFFSET_MATH = 3             #In Find_Source(), position of extra offset in source list
EX_ARG = 0                  #In Find_Source(), position of argument in extra index list
EX_INSTRUCTION = 1          #In Find_Source(), position of instuction in extra index list
EX_AMOUNT = 2               #In Find_Source(), position of extra offset in extra index list
CALL_ADDRESS = 0            #In Find_Source(), position of argument in new_func list
CALL_PARAMETER = 1          #In Source_Path(), position of parameter in new_func list
CALL_LOCATION = 2           #In Source_Path(), position of location in new_func list

#This helper function calculates the order in which the stack parameter was given to the function
def Push_Order(instruction):
    start = str(instruction).find("+")
    end = str(instruction).find("]")
    bad = str(instruction).find("*")
    if start == -1 or end == -1 or instruction[start+2] == '-' or bad != -1:
        return -1
    offset = instruction[start+2:end]
    size = int(offset,0)
    order = (size-8)/8
    return order

#This helper function calculates the offset for the stack parameter for the next function
def Push_Location(count, push_spot):
    order = count - push_spot
    stack_offset = hex(8*order + 16)
    full_stack_offset = "qword ptr [RBP + " + str(stack_offset) + "]"
    return full_stack_offset

#This helper function seperates the instruction into at most 3 parts (command, operand1, and operand2)
def Instruction_Split(instruction):
    operands = Listing.getInstructionAt(instruction.getMinAddress())
    if operands == None:
        return None, None, None
    command = instruction.getMnemonicString()
    operand1 = operands.getDefaultOperandRepresentation(0)
    operand2 = operands.getDefaultOperandRepresentation(1)
    return command, operand1, operand2

#This helper function gets the offset from within the instruction
def Get_Offset(instruction):
    beginning = instruction.find("-")
    end = None
    if beginning != -1:
        for i in range(beginning, len(instruction)):
            if instruction[i] == "]" or instruction[i] == " ":
                end = i
                break
        if end == None:
            return None
        return hex(int(instruction[beginning:end], 16))
    else:
        return None

#This helper fucntion gets the value that is used to add to offsets
def Get_Addition(instruction):
    beginning = instruction.find("+")
    bad = str(instruction).find("*")
    if beginning != -1 and instruction[beginning+2] != '-' and bad == -1:
        end = instruction.find("]")
        return (int(instruction[beginning+2:end],16))
    else:
        return -1

#This helper function finds the nearest local variable going down in the stack
def Nearest_Local(func, offset):
    closest = None
    diff = 0
    offset_size = None
    nearest_read = None
    for x in FunctionLocals[func].items():
        if int(offset,16) < int(x[0],16) and FunctionLocals[func][x[0]]["type"] == "WRITE":
            diff = int(x[0],16) - int(offset,16)
            if closest == None:
                closest = diff
            elif diff < closest:
                if FunctionLocals[func][x[0]]["block"] == 1:
                    closest = 0
                else:
                    closest = diff
        elif int(offset,16) < int(x[0],16) and FunctionLocals[func][x[0]]["type"] == "READ":
            diff = int(x[0],16) - int(offset,16)
            if closest == None:
                closest = diff
            elif diff < closest:
                if FunctionLocals[func][x[0]]["block"] == 1 and FunctionLocals[func][x[0]]["size"] > 1:
                    closest = diff
                else:
                    if nearest_read == None:
                        nearest_read = diff
                    elif nearest_read > diff:
                        nearest_read = diff
        elif int(offset,16) == int(x[0],16) and FunctionLocals[func][x[0]]["type"] == "WRITE":
            offset_size = FunctionLocals[func][x[0]]["block"]
    if offset_size and nearest_read and nearest_read < closest and offset_size > 1:
        closest = nearest_read
    return closest

#This helper function finds the Registers that are used in an operand
def Registers_Used(operand):
    reg_list = []
    for x in TopRegisters:
        if operand.find(x) != -1:
            reg_list.append(x)
    return reg_list

#This helper function is used to fill in the first use of the local variables. 
#This is used when strings are allocated on the stack.
def Local_Var_Usage(func):
    command = None          #The command portion of the instruction
    operand1 = None         #Used to as the first operand of an instruction
    operand2 = None         #Used to as the second operand of an instruction
    instruc = None          #current instruction
    var_list = {}           #dictionary of dictionaries of the variable length
    first_var_use = {}      #value used for the variable
    offset = None           #variable place in the stack
    func_var = func.getLocalVariables() #list of local variables for a function
    next_func = getFunctionAfter(func.getEntryPoint())  #Next Function
    address = func.getEntryPoint()  #current address
    offset_to_find = None   #Check to see instuction had a local variable
    find_reg = None         #Register to check for local variable usage
    last_instruc = None     #Previous instruction looked at
    last_command = None     #The command portion of the previous instruction
    last_operand1 = None    #Used to as the first operand of the previous instruction
    last_operand2 = None    #Used to as the second operand of the previous instruction
    found = False           #boolean used to track if the varable was found

    test = currentProgram.getReferenceManager()

    #Prevents double checking a function
    if FunctionLocals:
        if func in FunctionLocals:
            return
    #create local variable list from the function
    for x in func_var:
        references = RefMangager.getReferencesTo(x)
        offset = hex(x.getStackOffset()+8)
        var_len = x.getLength()
        var_list[offset] = {"size": var_len}
        no_write = True
        used = set([])
        for ref in references:
            if str(ref.getReferenceType()) == "WRITE":
                ref_offset = hex(int(Get_Offset(str(ref.getToAddress())),16)+8)
                if ref_offset in used:
                    continue
                used.add(ref_offset)
                if ref_offset != offset:
                    difference = var_len + (int(offset,16)-int(ref_offset,16))
                    var_list[ref_offset] = {"size": difference}

                instruc = Listing.getCodeUnitAt(ref.getFromAddress())
                full_instruc = Listing.getInstructionAt(ref.getFromAddress())
                if instruc == None:
                    continue
                command, operand1, operand2 = Instruction_Split(instruc)
                reg = full_instruc.getRegister(INST_FROM)
                if reg is not None:
                    track = reg.getBaseRegister()
                    last_instruc = instruc
                    found = False
                    #step backwards through the program to see the registers usage
                    while last_instruc.getMinAddress() != func.getEntryPoint():
                        last_instruc = Listing.getCodeUnitBefore(last_instruc.getMinAddress())
                        full_instruc = Listing.getInstructionAt(last_instruc.getMinAddress())
                        last_command, last_operand1, last_operand2 = Instruction_Split(last_instruc)
                        reg2 = full_instruc.getRegister(INST_TO)
                        if last_command == 'MOV' or last_command == "LEA":
                            if reg2 is not None:
                                reg_to_find = reg2.getBaseRegister()
                                if reg_to_find.getName() == track.getName():
                                   #if the value is in brackets with 0x, then it is an address  
                                    if last_operand2[11:13] == "0x" or last_operand2[0:3] == "[0x":
                                        open_bracket = last_operand2.find("[")
                                        close_bracket = last_operand2.find("]")
                                        just_address = last_operand2[open_bracket+1:close_bracket]
                                        address = AddressFactory.getAddress(just_address)
                                        if address == None:
                                            break
                                        last_code_unit = None
                                        address_listing = Listing.getDataAt(address)
                                        if address_listing == None:
                                            last_code_unit = Listing.getDefinedCodeUnitBefore(address).getMinAddress()
                                            address_listing = Listing.getDataBefore(address)
                                        #when the address contains a string
                                        if address_listing and address_listing.hasStringValue():
                                            address_offset = None
                                            if last_code_unit:
                                                address_offset = (int(str(address),16) - int(str(last_code_unit),16))/4
                                                tmp_string = len(str(address_listing.getValue()))
                                            if address_offset and address_offset == tmp_string:
                                                last_operand2 = '0x00'
                                            else:
                                                last_operand2 = '0x' + ('41'*var_list[ref_offset]["size"])
                                    first_var_use[ref_offset] = {"size": var_list[ref_offset]["size"], "value":last_operand2, "type":"WRITE", "block": var_len}
                                    found = True
                                    break
                    if found:
                        var_list.pop(ref_offset)
                        no_write = False
                        continue
                    else:
                        first_var_use[ref_offset] = {"size": var_list[ref_offset]["size"], "value":"0", "type":"WRITE", "block": var_len}
                        var_list.pop(ref_offset)
                        no_write = False
                        continue
                else:
                    first_var_use[ref_offset] = {"size": var_list[ref_offset]["size"], "value":operand2, "type":"WRITE", "block": var_len}
                    var_list.pop(ref_offset)
                    no_write = False
                    continue
        if no_write:
            first_var_use[offset] = {"size": var_list[offset]["size"], "value":"0", "type":"READ", "block": var_len}
    FunctionLocals[func] = first_var_use

#write the sources to a csv file
def Write_To_Csv(file_name, write_type, src, message_type, header):
    if header:
        with open(file_name, write_type) as file:
            writer = csv.writer(file)
            writer.writerow(["Type","Sink","Argument","Src Name","Function Found","Sink Location","Argument Location","Path","Size","Max Fill"])
    else:
        with open(file_name, write_type) as file:
            writer = csv.writer(file)
            writer.writerow([message_type,str(src.sink),str(src.arg),str(src.name),str(src.function),"0x"+str(src.ref_location),
                            "0x"+str(src.location.getMinAddress()),str(src.path),str(src.size),str(src.max_fill)])

#This class is used to search, create, and calculate the overflow of the sinks
class Sink_Handler():
    #This function will look for the sinks in the program 
    def Find_Sinks(self):
        sinks_used = []                     #List of the sinks 
        double = set([])                    #prevents duplicate functions being added
        function = getFirstFunction()       #The current function in the function database
        entry = None                        #Gets address of the sink
        refs = None                         #Gets the references to the sink
        args = {}                           #Dictionary of the sinks arguments

        #Interate through the functions
        while function is not None:
            #Filter out non sinks
            if function.getName() in Sinks_Args and function.getName() not in double:
                double.add(function.getName()) 
                entry = function.getEntryPoint()
                refs = getReferencesTo(entry) 
                args = Sinks_Args[function.getName()].copy() 
                #Get the references to this sink
                for x in refs:
                    sinks_used.append(Sinks(function.getName(), x.getToAddress(), x.getFromAddress(), args))
            #get next function
            function = getFunctionAfter(function)
        return sinks_used

    def Find_Overflows(self, sink):
        global OutputFile
        #Create csv file for overflows
        if OutputFile:
            file_name = ProgramName + '_overflows.csv'
            Write_To_Csv(file_name, 'w', None, None, True)
        OutputFile = False 
        #Calculating if the sinks can cause an overflow
        sink.Calculate_Overflow()

#This class is used to contain the informtion about the sinks
class Sinks():
    def __init__(self, name, location, ref_location, arguments, sources = None):
        self.name = name
        self.location = location
        self.ref_location = ref_location
        self.arguments = arguments
        self.sources = []

    #adds sources to the sink
    def Set_Sources(self, src):
        self.sources.extend(src)

    #Finds the overflow between the sources at the sinks
    def Calculate_Overflow(self):
        source = []             #list of the source value of the sink
        destination = []        #list of the destination value of the sink 
        num_to_copy = []        #list of the int values of the sink
        warning = False         #check to see if a warning was already issued
        num_arg = len(self.arguments)  #number of args for the sink

        #Used for determining two argument functions
        if num_arg == 2:
            for x in self.sources:
                if x.arg == "charptr1":
                    destination.append(x)
                else:
                    source.append(x)
            for i in source:
                for j in destination:
                    len1 = len(i.path)
                    len2 = len(j.path)
                    not_on_path  = True
                    if len1 >= len2:
                        for x in range(len2):
                            if i.path[x:x+1] != j.path[x:x+1]:
                                not_on_path = False
                    else:
                        for x in range(len1):
                            if i.path[x:x+1] != j.path[x:x+1]:
                                not_on_path = False
                    if not not_on_path:
                        continue

                    if i.max_fill > j.size:
                        warning = True
                        print("\nWarning! The source max fill size is larger than the allocated size for the destination.")
                        difference = i.max_fill - j.size
                        print("There is an over flow of: " + str(difference))
                        if difference == 1:
                            print("An overflow of one, may indicate that the compiler added an extra variable location for the null pointer." )
                        i.print_sources()
                        j.print_sources() 
                        file_name = ProgramName + '_overflows.csv'
                        Write_To_Csv(file_name, 'a', j, "Warning", False)
                        Write_To_Csv(file_name, 'a', i, "Warning", False)

                    if i.size > j.size and not warning:
                        print("Caution! The allocated size for the source is larger than the allocated size for the destination.")
                        i.print_sources()
                        j.print_sources()
                        file_name = ProgramName + '_overflows.csv'
                        Write_To_Csv(file_name, 'a', j, "Caution", False)
                        Write_To_Csv(file_name, 'a', i, "Caution", False)

        #Used for determining THREE argument functions
        elif num_arg == 3:
            for x in self.sources:
                if x.arg == "charptr1":
                    destination.append(x)
                elif x.arg == "charptr2":
                    source.append(x)
                else:
                    num_to_copy.append(x)
            for i in destination:
                for k in source:
                    len1 = len(i.path)
                    len2 = len(k.path)
                    larger = None
                    not_on_path  = True
                    if len1 >= len2:
                        larger = i.path
                        for x in range(len2):
                            if i.path[x:x+1] != k.path[x:x+1]:
                                not_on_path = False
                    else:
                        larger = k.path
                        for x in range(len1):
                            if i.path[x:-x+1] != k.path[x:x+1]:
                                not_on_path = False
                    if not not_on_path:
                        continue

                    for j in num_to_copy:
                        len1 = len(larger)
                        len2 = len(j.path)
                        not_on_path  = True
                        if len1 >= len2:
                            for x in range(len2):
                                if j.path[x:x+1] != larger[x:x+1]:
                                    not_on_path = False
                        else:
                            for x in range(len1):
                                if j.path[x:x+1] != larger[x:x+1]:
                                    not_on_path = False
                        if not not_on_path:
                            continue

                        if j.max_fill > i.size and k.max_fill > i.size:
                            warning = True
                            difference = j.max_fill - i.size
                            if difference == 1:
                                temp_offset = Get_Offset(i.name)
                                null_check = hex(int(temp_offset, 16) + i.size)
                                if FunctionLocals[i.function][str(null_check)]["value"] == "0x0":
                                    continue
                            print("\nWarning! The source max fill size is larger than the allocated size for the destination.")
                            print("There is an over flow of: " + str(difference))
                            i.print_sources()
                            k.print_sources()
                            j.print_sources() 
                            file_name = ProgramName + '_overflows.csv'
                            Write_To_Csv(file_name, 'a', i, "Warning", False)
                            Write_To_Csv(file_name, 'a', k, "Warning", False)
                            Write_To_Csv(file_name, 'a', j, "Warning", False)

                        if j.size > i.size and not warning and k.size > i.size:
                            print("Caution! The number of bytes to write is larger than the allocated size for the destination.")
                            i.print_sources()
                            k.print_sources()
                            j.print_sources() 
                            file_name = ProgramName + '_overflows.csv'
                            Write_To_Csv(file_name, 'a', i, "Caution", False)
                            Write_To_Csv(file_name, 'a', k, "Caution", False)
                            Write_To_Csv(file_name, 'a', j, "Caution", False)

#This class is used to control the search and the creation of sources
class Source_Handler():
    #This function gets the first references to the sinks and collects the sources
    def Get_Sources(self, sink):
        source_list = []                    #List of sources for this sink
        stack = []                          #Used to keep track of the function level when looking for sources
        inside_function = None              #Current function that needs to be searched
        entry_address = None                #Call entry point for the previous function checked
        cur_path = []                       #Keeps track of the current path from the sink to the source
        arguments = None                    #Dictionary of arguments to look for
        new_args = None                     #Dictionary of arguments that still need to be found 
        extra_index = []                    #List used to keep track of arguments refernced by adding to index
        sources = []                        #list of the source from the Sources class
        search = Source_Finder()
        global FindSourceLimit

        args = sink.arguments.copy()
        stack.append((sink.ref_location, args, []))

        #Iterate through the functions and match the references
        #to the functions (stops when stack is empty)
        while stack:
            entry_address, arguments, extra_index = stack.pop()
            inside_function = getFunctionBefore(entry_address)
            FunctionsUsed.add(inside_function)
            cur_path.append([inside_function, entry_address])
            path = cur_path[:]
            FindSourceLimit = 10

            #finds the source info and returns the parameters that still need to be found.
            make_sources, new_args, index = search.Find_Source(entry_address, arguments, extra_index)
            for x in make_sources:
                if len(x) == 4:
                    sources.append(Sources(sink.name,x[ARGUMENT],x[LOCATION], inside_function, sink.ref_location, x[INSTRUCTION], path, extra = x[OFFSET_MATH]))
                    GlobalSources.extend(sources[-1:])
                elif x[0] == 'int' and x[1][0:2] == "dw":
                    sources.append(Sources(sink.name,x[ARGUMENT],x[LOCATION], inside_function, sink.ref_location, x[INSTRUCTION], path, MAX_INT))
                    GlobalSources.extend(sources[-1:])
                else:
                    sources.append(Sources(sink.name,x[ARGUMENT],x[LOCATION], inside_function, sink.ref_location, x[INSTRUCTION], path))
                    GlobalSources.extend(sources[-1:])
            
            #If true all sources have been found
            if not new_args and not index:
                cur_path.pop()
            #Need to find the remainder of the sources
            else:   
                refs = getReferencesTo(inside_function.getEntryPoint())
                for x in refs:
                    ref_entry = x.getFromAddress()
                    ref_func = getFunctionBefore(ref_entry)
                    #Only add called references and dont duplicate functions on path
                    duplicate = False
                    for y in cur_path:
                        if y[0] == ref_func:
                            duplicate = True
                    if (str(x.getReferenceType()) == "UNCONDITIONAL_CALL" or str(x.getReferenceType()) == "COMPUTED_CALL") and not duplicate: #ref_func not in cur_path:
                        stack.append((x.getFromAddress(),new_args, index))
        
        sink.Set_Sources(sources)

    def Find_Source_Usage(self, sink):
        #Finds where the sources are used
        for src in sink.sources:
            src.Get_Source_Usage()
        #Second pass to fill in any missing information 
        SecondPass = True
        for src in sink.sources:   
            src.Get_Source_Usage() 
        SecondPass = False

#This class is used to search the code for the sources
class Source_Finder():
    #This function is used to find the values that come from strlen type functions
    #This function is capable of handling basic addition and multiplication equations
    def __Find_StrLen_Var(self, entry, value, str_len):
        prev_instruc = None     #CodeUnit to look at when walking backwards in function
        new_address = entry     #Address we are currently looking at
        next_func = getFunctionAfter(entry) #Next function from enty point
        track = "RDX"           #Value we are currently tracking
        equation_string = ""    #The equation for the strlen variable in the form of a string

        #starting right after the strlen call
        while new_address != next_func.getEntryPoint():
            next_instruc = Listing.getCodeUnitAt(new_address)
            command, operand1, operand2 = Instruction_Split(next_instruc)
            if command == "ADD":
                if equation_string == "":
                    #if wcslen is used divide by four to get proper value
                    if str_len == "wcslen":
                        equation_string = "((" + value + "/4)" + "+" + operand2 +")"
                    else:
                        equation_string = "(" + value + "+" + operand2 +")"
                else:
                    equation_string = "(" + equation_string + "+" + operand2 + ")"
            
            elif command == "LEA" or command == "MOV":
                if operand1 == "RDX" or operand1 == "RSI":
                    #If RAX then no additional math needed
                    if operand2 == "RAX":
                        return equation_string
                    else:
                        #Check to see if multiplication was used
                        if operand2.find("*") != -1:
                            begin = operand2.find("*")
                            end = operand2.find("]")
                            operand = operand2[begin+1:end]
                            #start new equation
                            if equation_string == "":
                                equation_string = "(" + value + "*" + operand + ")"
                            #Combine equation
                            else:
                                equation_string = "(" + equation_string + "*" + operand + ")"
                            return equation_string
                        else:
                            begin = operand2.find("+")
                            end = operand2.find("]")
                            operand = operand2[begin+1:end]
                            #start new equation
                            if equation_string == "":
                                #if wcslen is used divide by four to get proper value
                                if str_len == "wcslen":
                                    equation_string = "((" + value + "/4)" + "+" + operand +")"
                                else:
                                    equation_string = "(" + value + "+" + operand +")"
                            #Combine equation
                            else:
                                equation_string = "(" + equation_string + "+" + operand + ")"
                            return equation_string
            #gets the next address
            new_address = next_instruc.getMaxAddress().next()

    #Looks for the sources to the parameters we are looking for
    def Find_Source(self, entry_address, entry_arg, extra_index):
        new_address = None              #The address that will be looked at next
        args = entry_arg.copy()         #Copy of the arguments to look for
        tmp_args = {}                   #holds the arguments that are known to come from parameters
        index = []                      #Keeps track of arguments that were calculated based on offset math
        sources = []                    #List of sources for this function
        extra_math = {}                 #dictionary of local variables that used math to calculate offset
        push_counter = 0                #Keeps track of the number of pushes to look for
        curr_push = 1                   #Current push we are on
        prev_instruc = None             #CodeUnit to look at when walking backwards in function
        next_instruc = None             #CodeUnit to look at when walking forwards in function
        command = None                  #The command portion of the instruction
        instruc = None                  #Insturction from the listing (used to get register values)
        reg = None                      #Current register
        parent_reg = None               #Used to see if register has a parent register
        operand1 = None                 #Used to as the first operand of an instruction
        operand2 = None                 #Used to as the second operand of an instruction
        is_index = False                #Boolean to track if an argument was passed as an index
        parm_check = Registers.copy()   #Used to track parameters passed on registers
        parameters = {}                 #Local variables used in parameter passing
        pass_by_value = set([])         #set used to track when passed by value is used
        inside_function = getFunctionBefore(entry_address)  #current function
        #The function after current function. Used to only search inside this function
        if inside_function == None:
            return [], {}, []
        next_func = getFunctionAfter(inside_function.getEntryPoint())
        global FindSourceLimit

        #determine the local variables and their sizes
        Local_Var_Usage(inside_function)
        
        #Look through the arguments and determine how many pushes we need to look for
        for arg, value in args.items():
            if Push_Order(value) != -1:
                push_counter += 1

        #below code is for finding parameter that were passed to the function
        new_address = inside_function.getEntryPoint()
        reg_used = False
        #search from the beginning of the function
        while new_address != next_func.getEntryPoint() and args:
            next_instruc = Listing.getCodeUnitAt(new_address)
            if next_instruc == None:
                break
            command, operand1, operand2 = Instruction_Split(next_instruc)
            if command == 'MOV' or command == 'MOVSX' or command == 'MOVSXD' or command == 'MOVSS' or command == "LEA" or command == 'CVTTSS2SI':
                for reg in parm_check :
                    if operand1 == reg and reg != "RBP" and operand1 != "EAX":
                        reg_used = True
                        break
                    else:
                        if operand2 == reg and operand2 != "RSP" and operand1 != "EAX":
                            parameters[operand1] = operand2

                #Once a register is used stop looking for the parameter passing
                if reg_used:
                    break
            #gets the next address
            new_address = next_instruc.getMaxAddress().next()

        #figure out the extra offset first
        for extra in extra_index:
            pointers, new_args, index = self.Find_Source(entry_address, {extra[EX_ARG]:extra[EX_INSTRUCTION]}, [])
            if pointers:
                if pointers[0][LOCATION] in Registers:
                    if pointers[0][LOCATION] in parameters.keys(): 
                        index.append([arg, parameters[pointers[0][LOCATION]], extra[EX_AMOUNT]])
                    #tmp_args[extra[EX_ARG]] = parameters[pointers[0][LOCATION]]
                else:
                    if Get_Offset(pointers[0][LOCATION]) == None:
                        sources.append([extra[EX_ARG],pointers[0][LOCATION],pointers[0][INSTRUCTION]])
                    else:
                        new_offset = hex(int(Get_Offset(pointers[0][LOCATION]),16) + extra[EX_AMOUNT])
                        new_var = "[RBP + " + str(new_offset) + "]"
                        sources.append([extra[EX_ARG],new_var,pointers[0][INSTRUCTION]])
                    #extra_index.remove(extra)

        #starting at the reference location iterate up to the begining of the function
        new_address = entry_address
        while new_address != inside_function.getEntryPoint() and args:
            prev_instruc = Listing.getCodeUnitBefore(new_address)
            command, operand1, operand2 = Instruction_Split(prev_instruc)
            #Checking for the parameters that were used in the function
            if command == 'MOV' or command == 'MOVSX' or command == 'MOVSXD' or command == 'MOVSS' or command == "LEA" or command == 'CVTTSS2SI':
                instruc = Listing.getInstructionAt(prev_instruc.getMinAddress())
                reg = instruc.getRegister(INST_TO)
                for arg, value in args.items():
                    #If the parameters were passed by values, then check to see the order of the mov
                    #commands to determine its place in the stack.
                    if operand1.find("word ptr [RAX") != -1 and push_counter > 0:
                        #base of the pass by values parameter
                        if operand1.find("[RAX]") != -1:
                            operand_addition = 0
                        else:
                            operand_addition = Get_Addition(operand1)
                        value_addition = Get_Addition(value)
                        if value_addition != -1 and operand_addition != -1:
                            value_addition = value_addition - 16
                            #When the stack and parameter values equal, we have found its location
                            if value_addition == operand_addition:
                                args[arg] = operand2
                                pass_by_value.add(operand2)
                                push_counter -= 1
                            #When the stack position is less than the parameter, then the program moved
                            #values across different variables. This is common in structs of multiple strings.
                            elif operand_addition < value_addition:
                                prev_address = prev_instruc.getMaxAddress().next()
                                while prev_address != entry_address:
                                    tmp_prev_instruc = Listing.getCodeUnitAt(prev_address)
                                    tmp_command, tmp_operand1, tmp_operand2 = Instruction_Split(tmp_prev_instruc)
                                    if tmp_operand1.find("word ptr [RAX") != -1:
                                        args[arg] = tmp_operand2
                                        pass_by_value.add(tmp_operand2)
                                        push_counter -= 1
                                        break
                                    prev_address = tmp_prev_instruc.getMaxAddress().next()
                    
                    #checks to see if its a register
                    elif reg is not None:
                        #sometimes a lower register is used, so always get the parent register for the argument compare
                        parent_reg = reg.getParentRegister()
                        if parent_reg is None:
                            parent = ""
                        else:
                            parent = parent_reg.getName()
                        child = False
                        if value == "AL" and reg.getName().find("A") != -1:
                            child = True
                        #checks to see if the register is the value the function is looking for
                        if reg.getName() == value or parent == value or child:
                        #if reg_check and reg.getName() == reg_check.getName():
                            if arg in extra_math.keys() and value in extra_math[arg]:
                                is_index = False

                                #check to see if the value was used as a parameter
                                if operand2 in parameters:
                                    index.append([arg, parameters[operand2], extra_math[arg][value]])
                                    #tmp_args[arg] = parameters[operand2]
                                    args.pop(arg)
                                    extra_math.pop(arg)
                                    is_index = True
                                else:
                                    #checks to see if the value is an index to another value
                                    for x, y in args.items():
                                        if operand2 == y: 
                                            index.append([arg, operand2, extra_math[arg][value]])
                                            args.pop(arg)
                                            is_index = True
                                            break
                                #If not an index, it is a local varialbe
                                if not is_index:
                                    temp_offset = Get_Offset(operand2)
                                    if temp_offset and operand2.find("[RBP") != -1:
                                        new_offset = hex(int(temp_offset,16) + extra_math[arg][value])
                                        args[arg] = "[RBP + " + str(new_offset) + "]"
                                    else:
                                        temp_offset = Get_Addition(operand2)
                                        if temp_offset and operand2.find("[RBP") != -1:
                                            new_offset = hex(temp_offset + extra_math[arg][value])
                                            args[arg] = "qword ptr [RBP + " + str(new_offset) + "]"
                                            continue
                                        else:
                                            continue
                                else:
                                    continue

                            #convert RAX pointers to RAX (This is for searching for the right register)                
                            if operand2 == "qword ptr [RAX]":
                                args[arg] = "RAX"
                            elif operand2[0:14] == "qword ptr [RAX":
                                addition = Get_Addition(operand2)
                                if addition != -1:
                                    extra_math[arg] = {operand1:addition}
                                    args[arg] = "RAX"
                                    continue
                            else:
                                if operand1 in pass_by_value:
                                    begin = operand2.find("[")
                                    args[arg] = operand2[begin:]
                                else:
                                    args[arg] = operand2
                            check = args[arg]

                            #Check to see if the value came from a parameter
                            drop = False
                            for local, parm in parameters.items():
                                tmp_offset1 = Get_Offset(operand2)
                                tmp_offset2 = Get_Offset(local)
                                if tmp_offset1 and tmp_offset2 and tmp_offset1 == tmp_offset2:
                                    tmp_args[arg] = parm
                                    args.pop(arg)
                                    drop =True
                                    break
                            if drop:
                                continue

                            #If a register is used is used, then calculate the extra math for its actual source location
                            reg_list = Registers_Used(check)
                            #This program will exclude finding multiple registers when searching for the sources
                            if len(reg_list) > 1:
                                args.pop(arg)
                                continue
                            if reg_list:
                                if check.find("[" + reg_list[0] + " ") != -1:
                                    begining = check.find("0")
                                    end = check.find("]")
                                    if check[begining:end].find("+") != -1:
                                        #sources.append([arg,operand2,prev_instruc])
                                        args.pop(arg)
                                        continue
                                    else:    
                                        extra_math[arg] = {reg_list[0]:int(check[begining:end],16)}
                                    args[arg] = reg_list[0]
                                    continue
                                elif check.find("*") != -1:
                                    continue
                            
                            #if it's a local var, address, or constant, create soucre and remove from search list
                            if check[0:2] == "0x" or check[11:13] == "0x" or check[0:1] == "[" or check[0:2] == "dw":
                                if check.find("[RBP + 0x") != -1 :
                                    args[arg] = "qword ptr " + check
                                elif check.find("*") != -1:
                                    args.pop(arg)
                                else:
                                    sources.append([arg,check,prev_instruc])
                                    args.pop(arg)

                    #If not a register, checks to see if the pointer was used as parameter
                    else:
                        if operand1 == value:
                            drop = False
                            for local, parm in parameters.items():
                                tmp_offset1 = Get_Offset(operand2)
                                tmp_offset2 = Get_Offset(local)
                                if tmp_offset1 and tmp_offset2 and tmp_offset1 == tmp_offset2:
                                    tmp_args[arg] = parm
                                    args.pop(arg)
                                    drop = True
                                    break
                            if drop:
                                continue
                            else:
                                #if it's a local var, address, or constant, create soucre and remove from search list
                                if operand2[0:2] == "0x" or operand2[11:13] == "0x" or operand2[0:1] == "[" or operand2[0:2] == "dw":
                                    if operand2.find("[RBP + 0x") != -1 :
                                        args[arg] = "qword ptr " + operand2
                                    else:
                                        sources.append([arg,operand2,prev_instruc])
                                        args.pop(arg)
                                else:
                                    args[arg] = operand2


            #When there are pushes and the command is PUSH, perform the following checks 
            elif command == "PUSH" and push_counter:
                for arg, value in args.items():
                    if Push_Order(value) == curr_push:
                        original_value = entry_arg[arg]
                        stack_value = Get_Addition(original_value)
                        diff = stack_value % 8
                        if diff != 0:
                            op_offset = Get_Offset(operand1)
                            new_value = hex(int(op_offset,16) + diff)
                            operand1 = "qword ptr [RBP + " + str(new_value) + "]"
                        if operand1.find("qword") != -1:
                            start = operand1.find("[")
                            args[arg] = operand1[start:]
                            sources.append([arg,operand1,prev_instruc])
                            args.pop(arg)
                        elif operand1[0:1] == "[":
                            args[arg] = operand1
                            sources.append([arg,operand1,prev_instruc])
                            args.pop(arg)
                        else:    
                            args[arg] = operand1
                        push_counter -= 1
                        break
                curr_push += 1
            
            #When the command is ADD, perform the following checks
            elif command == "ADD":
                instruc = Listing.getInstructionAt(prev_instruc.getMinAddress())
                reg = instruc.getRegister(INST_TO)
                for arg, value in args.items():
                    if value == operand1:
                        #if operand1 in extra_math:
                        if operand2[0:2] == "0x":
                            extra_math[arg] = {operand1:int(operand2,16)}
            
            #When the command is a CALL or type of jump, stop looking for parameters
            elif command == "CALL" or command[0:1] == "J":
                if command == "CALL":
                    call_address = AddressFactory.getAddress(operand1)
                    if call_address != None:
                        call_func = getFunctionAt(call_address)
                        #Checks if function call is a string legnth type function
                        if call_func.getName() in String_Length:
                            if "int" in args:
                                #find the source info for the string legnth function
                                if FindSourceLimit > 0:
                                    FindSourceLimit -= 1
                                    int_src, left_over, left_over_index = self.Find_Source(prev_instruc.getMinAddress(), {"int":"RDI"}, [])
                                    if int_src:
                                        #If string length argument was used in an equation, figure out the equation
                                        equation = self.__Find_StrLen_Var(prev_instruc.getMinAddress(), int_src[0][LOCATION], call_func.getName())
                                        sources.append([arg,int_src[0][LOCATION],prev_instruc, equation])
                                        args.pop(arg)
                    else:
                        break

            #gets the next address
            new_address = prev_instruc.getMinAddress()

        #make sure local variable is not a pointer 
        for x in sources:
            new_address = inside_function.getEntryPoint()
            while new_address != next_func.getEntryPoint():
                pointers = None
                next_instruc = Listing.getCodeUnitAt(new_address)
                command, operand1, operand2 = Instruction_Split(next_instruc)
                if command == "MOV" and operand1 == "qword ptr " + x[LOCATION]:
                    pointers, new_args, index2 = self.Find_Source(next_instruc.getMinAddress(), {x[ARGUMENT]:operand2}, []) 
                if pointers:
                    test = pointers[0][LOCATION] not in Registers
                    if pointers[0][LOCATION] not in Registers and pointers[0][LOCATION].find("+") != -1:
                        x[LOCATION] = pointers[0][LOCATION]
                        x[INSTRUCTION] = pointers[0][INSTRUCTION]
                new_address = next_instruc.getMaxAddress().next()

        #Remove items that were not passed as parameters and could not be determined as a local variable
        for arg, value in args.items():
            if not value or value.find("-") != -1 or value.find("RBP") == -1:
                args.pop(arg)

        args.update(tmp_args)
        return sources, args, index

#This class is used to contain the information about the sources
class Sources():
    def __init__(self, sink, arg, name, function, ref_location, location, path, size = None, max_fill = None, usage = None, extra = None):
        self.sink = sink                    #The name of the sink
        self.arg = arg                      #The sources argument in the sink
        self.name = name                    #The operand used as the values/stack location for the sink 
        self.function = function            #The function the sink was found in
        self.ref_location = ref_location    #The sink call location
        self.location = location            #The location the source was found
        self.path = path                    #The function path to this source
        self.confident = False              #Confidence in the initial size calculations
        if usage:                           #List of how this source was used
            self.usage = usage
        else:
            self.usage = []
        if max_fill:                        #Largest found values to fill the source
            self.max_fill = max_fill
        else:
            self.max_fill = 0
        if size:                            #Allocated space for the source
            self.size = size
        else:
            self.size = self.__Calculate_Storage_Size(function)
        self.extra = extra                  #Equation for determinine the sources values
        
    #Function used to calculate the allocated space of the sources
    def __Calculate_Storage_Size(self, function):
        prev = None
        size = 0 
        beginning = 0
        end = 0
        stack_offset = 0
        search = Source_Finder()

        #if it starts with 0x then it is a value/address to data section
        if self.name[0:2] == "0x":
            #when the argument is an int then we know its a value
            if self.arg == "int":
                if self.sink == "wcsncat" or self.sink == "wcsncpy":
                    size = int(self.name,0)*4
                else:
                    size = int(self.name,0)
                self.max_fill = size
            #used when its a address
            else:
                address = AddressFactory.getAddress(self.name)
                address_listing = Listing.getDataAt(address)
                #When the address contains a string
                if address_listing and address_listing.hasStringValue():
                    size = len(str(address_listing.getValue()))
                    self.max_fill = size
                else:
                    size = 0
        #if the value is in brackets with 0x, then it is an address  
        elif self.name[11:13] == "0x" or self.name[0:3] == "[0x":
            open_bracket = self.name.find("[")
            close_bracket = self.name.find("]")
            just_address = self.name[open_bracket+1:close_bracket]
            address = AddressFactory.getAddress(just_address)
            if address == None:
                return size
            address_listing = Listing.getDataAt(address)
            #when the address contains a string
            if address_listing and address_listing.hasStringValue():
                if str(address_listing.getBaseDataType()) == "unicode32":
                    size = len(str(address_listing.getValue()))*4
                else:
                    size = len(str(address_listing.getValue()))
                self.max_fill = size
            #when the address is not initialized, find its references
            #this means the address is in the bss section
            #the commented out code is an way to figure out a value
            else:
                address_ref = getReferencesTo(address) 
                tmp_size = 0 
                for x in address_ref:
                    #Find values that wrote to this address
                    if str(x.getReferenceType()) == "WRITE":
                        ref = x.getFromAddress()
                        next_instruc = Listing.getCodeUnitAt(ref)
                        new_address = next_instruc.getMaxAddress().next()
                        sources, new_args, index = search.Find_Source(new_address, {self.arg:self.name}, [])
                        if sources > 0:
                            self.name = sources[0][1]
                            self.location = sources[0][2]
                            tmp_address = self.location.getMinAddress()
                            self.function = getFunctionBefore(tmp_address)
                            self.path = [self.path[0], [self.function, tmp_address]]
                            size = self.__Calculate_Storage_Size(self.function)

        #If the value has a '-' then it is local variable
        #at this point the most we can determine is the number of bytes between the local variables
        else:
            beginning = self.name.find("-")
            if beginning != -1:
                for i in range(beginning, len(self.name)):
                    if self.name[i] == "]" or self.name[i] == " ":
                        end = i
                        break
                try:
                    stack_offset = int(self.name[beginning:end], 16) - 8
                except ValueError:
                    return size
                if stack_offset == None:
                    return size
                #Calculate the space between the local varialbes
                for x in function.getLocalVariables():
                    if stack_offset == x.getStackOffset():
                        if prev:
                            size = x.getStackOffset() - prev
                        else:
                            size = stack_offset + 8
                        if x.getLength() == 1:
                            self.confident = True
                        break
                    elif stack_offset > x.getStackOffset():
                        if prev == None:
                            return size
                        size = stack_offset - prev
                        break
                    prev = x.getStackOffset()
                
        return abs(size)

    #This function tracks the sources usage through the program
    def Get_Source_Usage(self):
        stack = []              #Used to keep track of the function level when looking for sources
        start_address = None    #entry point to begin looking for the source usage
        src = None              #source object that we are currently looking at
        search_term = None      #The operand we are trying to find
        new_func = []           #list of the functions that use the source
        address = None          #address of the called function
        called_func = None      #Function of the called address
        num_of_arg = None       #number of arguments the sink uses
        duplicate = set([])     #keeps track of the functions used

        #Dont look for sources that are constants or addresses
        if self.name[0:2] == "0x":
            return
        
        #add the sources to the stack
        #for x in sources:
        stack.append((self.path[-1][0].getEntryPoint(), self.name))

        #while the stack still has sources to find
        while stack:
            start_address, search_term = stack.pop()
            #returns a list of calls that the source was used in
            new_func = self.__Source_Usage(start_address, search_term)
            for x in new_func:
                address = AddressFactory.getAddress(x[CALL_ADDRESS])
                called_func = getFunctionAt(address)
                #if the source was used in a sink determine its fill values
                if called_func.getName() in Sinks_Args:
                    num_of_arg = len(Sinks_Args[called_func.getName()])
                    #if value is rdi, that means that the variable is being filled.
                    if x[CALL_PARAMETER] == "RDI":
                        for i in GlobalSources:
                            if i.ref_location == x[CALL_LOCATION]:
                                if num_of_arg == 2:
                                    if i.arg == "charptr2" or i.arg == "int":
                                        if self.max_fill < i.max_fill:
                                            self.max_fill = i.max_fill
                                elif num_of_arg == 3:
                                    if i.arg == "int":
                                        if self.max_fill < i.max_fill:
                                            self.max_fill = i.max_fill
                #if call is not a sink, add the call to the stack
                else:
                    check = str(address) + " " + str(x[CALL_PARAMETER])
                    if check not in duplicate:
                        stack.append((called_func.getEntryPoint(), x[CALL_PARAMETER]))
                        FunctionsUsed.add(called_func)
                        duplicate.add(str(address) + " " + str(x[CALL_PARAMETER]))

    #This function is used to fill in some of the gaps in knowledge about how the sources
    #is used and the values that it is filled with.
    def __Source_Usage(self, start_address, search_term):
        called_func =[]         #List used to keep track of the functions that use the source
        push_counter = 0        #Keeps track of the number of pushes to look for
        push_order = 0          #Keeps track of the push the variable is used in
        local_var = None        #The local variable we are looking for
        command = None          #The command portion of the instruction
        operand1 = None         #Used to as the first operand of an instruction
        operand2 = None         #Used to as the second operand of an instruction
        first = True            #This is for the first use of a parameter that was passed as a register
        track = None            #The item that we are following for its next use
        prev_track = None       #The last non register value tracked
        next_instruc = None     #The instrunction we are looking at
        new_address = None      #The address we are looking at
        func_address = None     #The that a call instruction uses
        address = None          #address of the called function
        check_func = None       #Function of the called address
        new_args = None         #Dictionary of arguments that still need to be found 
        index = []              #List used to keep track of arguments refernced by adding to index
        sources = []            #list of the source from the Sources class
        fill = 0                #int used in memset or wmemset
        func = None             #function we are currently in
        found = 0               #int used to determine if the local variable is in the instruction
        search = Source_Finder()
        next_func = getFunctionAfter(start_address).getEntryPoint()        

        #determine the local variables and their sizes
        Local_Var_Usage(getFunctionBefore(start_address))

        #if the source was passed as a register, then its first usage needs to be found
        if search_term in Registers:
            local_var = None
        #if the source is not a register, then it is a local variable
        else: 
            local_var = search_term
            first = False
        track = search_term
        new_address = start_address
        #starting at the beginning of the function and iterating to the bottom of the function
        while new_address != next_func:
            next_instruc = Listing.getCodeUnitAt(new_address)
            command, operand1, operand2 = Instruction_Split(next_instruc)
            #if MOV or LEA are used check to see if the source is affected
            if command == 'MOV' or command == "LEA":
                if track == operand2:
                    track = operand1
                    #This is for the first use of a parameter that was passed as a register
                    if first:
                        local_var = track
                        first = False
                elif local_var == operand2:
                    track = operand1

                if track not in Registers:
                    prev_track = track

            #if call is used check to see if the source is used in a register or on stack for the call
            elif command == 'CALL':
                if local_var != track or push_order:
                    if push_order:
                        track = Push_Location(push_counter, push_order)
                    func_address = str(next_instruc)[5:]
                    address = AddressFactory.getAddress(func_address)
                    if address != None:
                        check_func = getFunctionAt(address)
                        if check_func.getName() == "memset":
                            sources, new_args, index = search.Find_Source(next_instruc.getMinAddress(), {"int":"RDX"}, [])
                            if sources:
                                try:
                                    fill = int(sources[0][LOCATION],16)
                                    if fill > self.max_fill:
                                        self.max_fill = fill
                                except ValueError:
                                    pass
                        elif check_func.getName() == "wmemset":
                            sources, new_args, index = search.Find_Source(next_instruc.getMinAddress(), {"int":"RDX"}, [])
                            if sources:
                                try:
                                    fill = int(sources[0][LOCATION],16)*4
                                    if fill > self.max_fill:
                                        self.max_fill = fill
                                except ValueError:
                                    pass
                        else:
                            called_func.append((func_address,track,new_address))
                        self.usage.append(str(new_address) + ' ' + str(next_instruc)+ " using " +str(track))
                        if prev_track:
                            track = prev_track
                        else:
                            track = local_var
                else:
                    if prev_track:
                        track = prev_track
                    else:
                        track = local_var
                push_counter = 0
                push_order = 0
            elif command == 'PUSH':
                push_counter += 1
                if track == operand1 or local_var == operand1:
                    push_order = push_counter

            #Adds every occurance of the source to the sources usage list and
            #checks the size of the local variables 
            if local_var:
                func = getFunctionAt(start_address)
                found = str(next_instruc).find(local_var)
                if found != -1:
                    if SecondPass:
                        self.usage.append(str(new_address) + ' ' + str(next_instruc))    
            new_address = next_instruc.getMaxAddress().next()
        if local_var:
            self.__Calculate_String_Var_Len(func, local_var)
        return called_func

    #This function figures out the length of the stack allocated strings
    def __Calculate_String_Var_Len(self, func, var_to_find):
        total_size = 0          #keeps track of the space initialized for the local variable
        alloc_size = 0          #keeps track of the space allocated for the local variable
        prev_size = 0           #keeps track of the space used by the previous offset
        src_var = False         #identifies when the source object is the same as a local variable
        name_offset = 0         #the offset from the source object
        offset = 0              #offset of the parameter we are looking for
        first_offset = 0        #saves the original offset
        space = 0               #stack space that avialable to the local variable
        used = 0                #stack space that was used for the local variable
        used_space = 0          #check to see if the space was filled completely
        last_chunk = 0          #last part of initialized value
        first = False           #checks used on the first iteration of getting the allocated size
        begin = 0               #start of the local variable in the equation
        end = 0                 #end of the local variable in the equation
        extra_offset = 0        #offset for the value in the equation
        equation = ""           #equation used to determine the size of the local variable
        size = 0                #the value that the equation produces

        #Check all the local variables in the function
        if func in FunctionLocals:
            name_offset = Get_Offset(self.name)
            offset = Get_Offset(var_to_find)
            #If the local variable and source offset are the same then that is the 
            #begining of the source.
            if name_offset == offset and offset:
                src_var = True
            first_offset = offset
            #Used for values initialized on the stack
            while offset != None and offset in FunctionLocals[func]:
                if FunctionLocals[func][offset]["value"][0:2] == "0x":
                    space = FunctionLocals[func][offset]["size"]
                    used = len(FunctionLocals[func][offset]["value"])-2
                    if self.sink == "wcscpy" or self.sink == "wcsncpy" or self.sink == "wcscat" or self.sink == "wcsncat":
                        used += 6
                    #if size is one then it is at the end of the initialized values
                    #(usually a null byte)
                    if FunctionLocals[func][offset]["size"] == 1:
                        total_size += 1
                        break
                    used_space = used/space
                    #When used_space is two then the space was completely filled
                    if used_space == 2:
                        total_size += space
                        offset = hex(int(offset,16)+space)
                    #When not completely filled that is the end of the initialized values
                    else:
                        last_chunk = used/2
                        total_size += last_chunk
                        break
                else:
                    break
            #adjust the max fill of the source object
            if self.max_fill < total_size:
                self.max_fill = total_size
            
            #Used to determine the allocated size of the variable
            #simple check to determine if prevous space is larger than next space
            #when next space is larger, it is the start of a new variable
            #***Note*** This will not be accurate in every instacne
            if self.confident:
                return
            offset = first_offset
            first = True
            closest_local = None
            extra = 0
            if offset != None:
                val = int(offset, 16) - 8
                for x in func.getLocalVariables():
                    if val == x.getStackOffset() or val in FunctionLocals[func]:
                        closest_local = val
                        extra = 0
                        break
                    elif val > x.getStackOffset():
                        break
                    else:
                        extra = x.getStackOffset() - val
                        closest_local = x.getStackOffset()
                if closest_local:
                    offset = hex(closest_local+8)
                alloc_size += extra

            while offset != None and offset in FunctionLocals[func]:
                if first:
                    prev_size = FunctionLocals[func][offset]["size"]
                    first = False
                space = FunctionLocals[func][offset]["size"]
                if prev_size < space:
                    break
                alloc_size += space
                prev_size = space
                offset = hex(int(offset,16)+space)
            if offset != None and prev_size != None:
                temp = hex(int(offset,16)-prev_size)
                nearest = Nearest_Local(func,temp)
                if nearest and nearest > 8:
                    alloc_size += nearest - prev_size
    
            #adjust the size of the source object
            if src_var and alloc_size > self.size:
                if self.extra is not None:
                    begin = self.extra.find("[")
                    end = self.extra.find("]")
                    extra_offset = Get_Offset(self.extra[begin:end+1])
                    #calculate extra equation for the source with the local variable information
                    if extra_offset and extra_offset in FunctionLocals[func]:
                        if self.sink == "wcsncat" or self.sink == "wcsncpy":
                            equation = self.extra.replace(self.extra[begin:end+1],str(alloc_size*4))
                        else:                    
                            equation = self.extra.replace(self.extra[begin:end+1],str(alloc_size))
                        size = eval(equation)
                        self.size = size
                else:
                    self.size = alloc_size

    #Displays the souces information
    def print_sources(self):
        print("Source Info")
        print("\tSink: " + str(self.sink))
        print("\tArgument: " + str(self.arg))
        print("\tName: " + str(self.name))
        print("\tFuncion: " + str(self.function))
        print("\tRef Location: " + str(self.ref_location))
        print("\tVar Location: " + str(self.location.getMinAddress()))
        print("\tPath: " + str(self.path))
        print("\tSize: " + str(self.size))
        print("\tMax Fill: " + str(self.max_fill))
        print("\tUsage: " + str(self.usage))
        print("\tExtra: " + str(self.extra))

if __name__ == "__main__":
    source_list = []            #list of the sources to the sinks
    sink_handler = Sink_Handler()
    source_handler = Source_Handler()

    print("This script is intended to be run on Ghidra version 9.1-BETA")
    print("You are currently running Ghidra " + getGhidraVersion() + "\n")

    #Find all the sinks used in the program
    sink_list = sink_handler.Find_Sinks()    

    #Find the souces for the sinks
    for sink in sink_list:
        source_handler.Get_Sources(sink)
    
    #Finds where the sources are used
    for sink in sink_list:
        source_handler.Find_Source_Usage(sink)
    
    #Calculates if the sinks can cause an overflow
    for sink in sink_list:
        sink_handler.Find_Overflows(sink)

    #Write all sources to a CSV file
    file_name = ProgramName + '_all_sources.csv'
    Write_To_Csv(file_name, 'w', None, None, True)
    for i in GlobalSources:
        Write_To_Csv(file_name, 'a', i, "N/A", False)
       
