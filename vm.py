class Program:

    def __init__(self):
        self.memory = [0 for i in range(0xFFFF)]
        self.vars = {} # dictionary for variables
        self.stack = [0 for i in range(0xFFFF)]
        self.register = {"rax": 0,
            "rbx": 0, 
            "rcx": 0, 
            "rdx": 0, 
            "rsi": 0,
            "rdi": 0,
            "rbp": 0,
            "rsp": 0,
            "r8": 0,
            "r9": 0,
            "r10": 0,
            "r11": 0,
            "r12": 0,
            "r13": 0,
            "r14": 0,
            "r15": 0}
        self.eflags = [0, 0] # sign flag, zero flag # sign flag gets set(=1) when the result of a comparison (cmp) is negative # zero flag gets set(=1) when the result of a cmp is 0
        self.ip = 0
        self.labels = {} # dictionary for labels

    def loadData(self, program): # load data section
        lines = program.split("\n")
        if lines[0].strip().strip("\n") != ".DATA:": # check for section start
            return
        j = 1
        aux = lines[j].strip().strip("\n")
        while aux != "END DATA": # check for section end
            var = aux.strip().strip("\n")
            var = var.split(" ")
            if len(var) != 2:
                raise Exception("Invalid data definition!")
            strr = False
            if '"' in var[1]: # check whether the variable is string or int
                strr = True
            arr = False
            if '[' in var[1] and ']' in var[1]: # check whether the variable is an array
                arr = True
            if not strr and not arr:
                val = int(var[1])
                if val > 0xFF:
                    raise Exception("Max int value is 255 on line " + str(j) + ": " + aux)
                b = bytearray(val.to_bytes(2, "little"))
                self.memory[self.ip] = b[0]
                self.memory[self.ip + 1] = b[1]
                self.vars[var[0]] = {"type": "int", "idx": self.ip}
                self.ip += 2
            elif not arr:
                vstr = var[1].split('"')[1].split('"')[0]
                self.vars[var[0]] = {"type": "str", "idx": self.ip}
                for i in range(len(vstr)):
                    self.memory[self.ip] = vstr[i]
                    self.ip += 1
                self.memory[self.ip] = 0 # terminate string with \x00
                self.ip += 1
            else:
                vlen = int(var[1].split('[')[1].split(']')[0])
                self.vars[var[0]] = {"type": "arr", "idx": self.ip, "len": vlen}
                for i in range(vlen):
                    self.memory[self.ip] = 0
                    self.ip += 1
            j += 1
            aux = lines[j].strip().strip("\n")

    def loadProgram(self, program):
        lines = program.split("\n")
        i = 0
        aux = lines[i].strip().strip("\n")
        while aux != ".CODE:": # skip data section if it exists
            i += 1
            aux = lines[i].strip().strip("\n")
        i += 1
        j = i
        aux = lines[i].strip().strip("\n")
        ipcc = self.ip
        while aux != "END CODE": # pass for defining labels
            instr = aux.split(" ")
            if len(instr) == 1:
                if ":" not in instr[0]:
                    raise Exception("Invalid label format in line " + str(i) + ": " + aux)
                self.labels[instr[0].split(":")[0]] = {"idx": ipcc}
                j += 1
                aux = lines[j].strip().strip("\n")
                continue
            if instr[0] not in ["mov", "add", "sub", "cmp", "inc", "dec", "jmp", "je", "ja", "jb", "jne", "jna", "jnb", "lea", "int", "push", "pop", "lodb", "stob"]:
                raise Exception("Invalid instruction")
            match instr[0]:
                case "mov":
                    ipcc += 4
                case "add":
                    ipcc += 4
                case "sub":
                    ipcc += 4
                case "cmp":
                    ipcc += 4
                case "inc":
                    ipcc += 2
                case "dec":
                    ipcc += 2
                case "jmp":
                    ipcc += 2
                case "je":
                    ipcc += 2
                case "ja":
                    ipcc += 2
                case "jb":
                    ipcc += 2
                case "jne":
                    ipcc += 2
                case "jna":
                    ipcc += 2
                case "jnb":
                    ipcc += 2
                case "lea":
                    ipcc += 3
                case "int":
                    ipcc += 2
                case "push":
                    ipcc += 2
                case "pop":
                    ipcc += 2
                case "lodb":
                    ipcc += 4
                case "stob":
                    ipcc += 3
            j += 1
            aux = lines[j].strip().strip("\n")
        ipc = self.ip
        aux = lines[i].strip().strip("\n")
        while aux != "END CODE": # pass for creating opcodes
            instr = aux.split(" ")
            if len(instr) == 1:
                if instr[0].split(":")[0] not in self.labels.keys():
                    raise Exception("Invalid instruction at line " + str(i) + ": " + aux)
                i += 1
                aux = lines[i].strip().strip("\n")
                continue
            if instr[0] not in ["mov", "add", "sub", "cmp", "inc", "dec", "jmp", "je", "ja", "jb", "jne", "jna", "jnb", "lea", "int", "push", "pop", "lodb", "stob"]:
                raise Exception("Invalid instruction at line " + str(i) + ": " + aux)
            match instr[0]:
                case "mov": # move value from register/variable/immediate to register/variable
                    vals = instr[1].split(",")
                    if vals[0] not in self.register.keys() and vals[0] not in self.vars.keys(): # ensure first operand is registry or variable
                        raise Exception("Invalid operand in line " + str(i) + ": " + aux)
                    if '"' in vals[1]: # ensure no string literals passed as second argument
                        raise Exception("Cannot use mov on string literals. Line  " + str(i) + ": " + aux)
                    if any(c.isalpha() for c in vals[1]) and vals[1] not in self.register.keys() and vals[1] not in self.vars.keys(): # ensure that int passed as second argument doesn't contain letter
                        raise Exception("Invalid literal in line" + str(i) + ": " + aux)

                    self.memory[ipc] = 0xE0

                    if vals[0] in self.register.keys():
                        self.memory[ipc + 1] = list(self.register.keys()).index(vals[0])
                    else:
                        if self.vars[vals[1]]["type"] != "int":
                            raise Exception("Cannot use mov on string/array literals. Line  " + str(i) + ": " + aux)
                        self.memory[ipc + 1] = list(self.vars.keys()).index(vals[0]) + 0x20

                    if vals[1] in self.register.keys():
                        self.memory[ipc + 2] = 'r' # hack, used to denote register
                        self.memory[ipc + 3] = list(self.register.keys()).index(vals[1])
                    elif vals[1] in self.vars.keys():
                        if self.vars[vals[1]]["type"] != "int":
                            raise Exception("Cannot use mov on string/array literals. Line  " + str(i) + ": " + aux)
                        idx = self.vars[vals[1]]["idx"]
                        self.memory[ipc + 2] = self.memory[idx]
                        self.memory[ipc + 3] = self.memory[idx + 1]
                    else:
                        if int(vals[1]) > 0xFF:
                            raise Exception("Max int value is 255 on line " + str(i) + ": " + aux)
                        b = bytearray(int(vals[1]).to_bytes(2, "little"))
                        self.memory[ipc + 2] = b[0]
                        self.memory[ipc + 3] = b[1]

                    ipc += 4

                case "add": # add value to register/variable from register/variable/immediate
                    vals = instr[1].split(",")
                    if vals[0] not in self.register.keys() and vals[0] not in self.vars.keys(): # ensure first operand is registry or variable
                        raise Exception("Invalid operand in line " + str(i) + ": " + aux)
                    if '"' in vals[1]: # ensure no string literals passed as second argument
                        raise Exception("Cannot use add on string literals. Line  " + str(i) + ": " + aux)
                    if any(c.isalpha() for c in vals[1]) and vals[1] not in self.register.keys() and vals[1] not in self.vars.keys(): # ensure that int passed as second argument doesn't contain letter
                        raise Exception("Invalid literal in line" + str(i) + ": " + aux)

                    self.memory[ipc] = 0xE1

                    if vals[0] in self.register.keys():
                        self.memory[ipc + 1] = list(self.register.keys()).index(vals[0])
                    else:
                        if self.vars[vals[1]]["type"] != "int":
                            raise Exception("Cannot use add on string/array literals. Line  " + str(i) + ": " + aux)
                        self.memory[ipc + 1] = list(self.vars.keys()).index(vals[0]) + 0x20

                    if vals[1] in self.register.keys():
                        self.memory[ipc + 2] = 'r' # hack, used to denote register
                        self.memory[ipc + 3] = list(self.register.keys()).index(vals[1])
                    elif vals[1] in self.vars.keys():
                        if self.vars[vals[1]]["type"] != "int":
                            raise Exception("Cannot use mov on string/array literals. Line  " + str(i) + ": " + aux)
                        idx = self.vars[vals[1]]["idx"]
                        self.memory[ipc + 2] = self.memory[idx]
                        self.memory[ipc + 3] = self.memory[idx + 1]
                    else:
                        if int(vals[1]) > 0xFF:
                            raise Exception("Max int value is 255 on line " + str(i) + ": " + aux)
                        b = bytearray(int(vals[1]).to_bytes(2, "little"))
                        self.memory[ipc + 2] = b[0]
                        self.memory[ipc + 3] = b[1]

                    ipc += 4

                case "sub": # subtract value to register/variable from register/variable/immediate
                    vals = instr[1].split(",")
                    if vals[0] not in self.register.keys() and vals[0] not in self.vars.keys(): # ensure first operand is registry or variable
                        raise Exception("Invalid operand in line " + str(i) + ": " + aux)
                    if '"' in vals[1]: # ensure no string literals passed as second argument
                        raise Exception("Cannot use sub on string literals. Line  " + str(i) + ": " + aux)
                    if any(c.isalpha() for c in vals[1]) and vals[1] not in self.register.keys() and vals[1] not in self.vars.keys(): # ensure that int passed as second argument doesn't contain letter
                        raise Exception("Invalid literal in line" + str(i) + ": " + aux)

                    self.memory[ipc] = 0xE2

                    if vals[0] in self.register.keys():
                        self.memory[ipc + 1] = list(self.register.keys()).index(vals[0])
                    else:
                        if self.vars[vals[1]]["type"] != "int":
                            raise Exception("Cannot use sub on string/array literals. Line  " + str(i) + ": " + aux)
                        self.memory[ipc + 1] = list(self.vars.keys()).index(vals[0]) + 0x20

                    if vals[1] in self.register.keys():
                        self.memory[ipc + 2] = 'r' # hack, used to denote register
                        self.memory[ipc + 3] = list(self.register.keys()).index(vals[1])
                    elif vals[1] in self.vars.keys():
                        if self.vars[vals[1]]["type"] != "int":
                            raise Exception("Cannot use mov on string/array literals. Line  " + str(i) + ": " + aux)
                        idx = self.vars[vals[1]]["idx"]
                        self.memory[ipc + 2] = self.memory[idx]
                        self.memory[ipc + 3] = self.memory[idx + 1]
                    else:
                        if int(vals[1]) > 0xFF:
                            raise Exception("Max int value is 255 on line " + str(i) + ": " + aux)
                        b = bytearray(int(vals[1]).to_bytes(2, "little"))
                        self.memory[ipc + 2] = b[0]
                        self.memory[ipc + 3] = b[1]

                    ipc += 4

                case "cmp": # compare value of register/variable with register/variable/immediate
                    vals = instr[1].split(",")
                    if vals[0] not in self.register.keys() and vals[0] not in self.vars.keys(): # ensure first operand is registry or variable
                        raise Exception("Invalid operand in line " + str(i) + ": " + aux)
                    if '"' in vals[1]: # ensure no string literals passed as second argument
                        raise Exception("Cannot use cmp on string literals. Line  " + str(i) + ": " + aux)
                    if any(c.isalpha() for c in vals[1]) and vals[1] not in self.register.keys() and vals[1] not in self.vars.keys(): # ensure that int passed as second argument doesn't contain letter
                        raise Exception("Invalid literal in line" + str(i) + ": " + aux)

                    self.memory[ipc] = 0xE3

                    if vals[0] in self.register.keys():
                        self.memory[ipc + 1] = list(self.register.keys()).index(vals[0])
                    else:
                        if self.vars[vals[0]]["type"] != "int":
                            raise Exception("Cannot use cmp on string/array literals. Line  " + str(i) + ": " + aux)
                        self.memory[ipc + 1] = list(self.vars.keys()).index(vals[0]) + 0x20

                    if vals[1] in self.register.keys():
                        self.memory[ipc + 2] = 'r' # hack, used to denote register
                        self.memory[ipc + 3] = list(self.register.keys()).index(vals[1])
                    elif vals[1] in self.vars.keys():
                        if self.vars[vals[1]]["type"] != "int":
                            raise Exception("Cannot use cmp on string/array literals. Line  " + str(i) + ": " + aux)
                        idx = self.vars[vals[1]]["idx"]
                        self.memory[ipc + 2] = self.memory[idx]
                        self.memory[ipc + 3] = self.memory[idx + 1]
                    else:
                        if int(vals[1]) > 0xFF:
                            raise Exception("Max int value is 255 on line " + str(i) + ": " + aux)
                        b = bytearray(int(vals[1]).to_bytes(2, "little"))
                        self.memory[ipc + 2] = b[0]
                        self.memory[ipc + 3] = b[1]

                    ipc += 4

                case "inc": # increment register/variable
                    if instr[1] not in self.register.keys() and instr[1] not in self.vars.keys(): # ensure first operand is registry or variable
                        raise Exception("Invalid operand in line " + str(i) + ": " + aux)

                    self.memory[ipc] = 0xE4
                    if instr[1] in self.register.keys():
                        self.memory[ipc + 1] = list(self.register.keys()).index(instr[1])
                    else:
                        if self.vars[instr[1]]["type"] == "int":
                            self.memory[ipc + 1] = list(self.vars.keys()).index(instr[1]) + 0x20
                        else:
                            raise Exception("Cannot inc strings/arrays. Line " + str(i) + ": " + aux)

                    ipc += 2

                case "dec": # decrement register/variable
                    if instr[1] not in self.register.keys() and instr[1] not in self.vars.keys(): # ensure first operand is registry or variable
                        raise Exception("Invalid operand in line " + str(i) + ": " + aux)

                    self.memory[ipc] = 0xE5
                    if instr[1] in self.register.keys():
                        self.memory[ipc + 1] = list(self.register.keys()).index(instr[1])
                    else:
                        if self.vars[instr[1]]["type"] == "int":
                            self.memory[ipc + 1] = list(self.vars.keys()).index(instr[1]) + 0x20
                        else:
                            raise Exception("Cannot dec strings/arrays. Line " + str(i) + ": " + aux)

                    ipc += 2

                case "jmp": # jump to label
                    if instr[1] not in self.labels.keys(): # ensure first operand is label
                        raise Exception("Invalid label for jump at line " + str(i) + ": " + aux)

                    self.memory[ipc] = 0xE6
                    self.memory[ipc + 1] = self.labels[instr[1]]["idx"]

                    ipc += 2

                case "je": # jump to label if equal
                    if instr[1] not in self.labels.keys(): # ensure first operand is label
                        raise Exception("Invalid label for jump at line " + str(i) + ": " + aux)

                    self.memory[ipc] = 0xE7
                    self.memory[ipc + 1] = self.labels[instr[1]]["idx"]

                    ipc += 2
                    
                case "ja": # jump to label if above
                    if instr[1] not in self.labels.keys(): # ensure first operand is label
                        raise Exception("Invalid label for jump at line " + str(i) + ": " + aux)

                    self.memory[ipc] = 0xE8
                    self.memory[ipc + 1] = self.labels[instr[1]]["idx"]

                    ipc += 2
                    
                case "jb": # jump to label if below
                    if instr[1] not in self.labels.keys(): # ensure first operand is label
                        raise Exception("Invalid label for jump at line " + str(i) + ": " + aux)

                    self.memory[ipc] = 0xE9
                    self.memory[ipc + 1] = self.labels[instr[1]]["idx"]

                    ipc += 2
                    
                case "jne": # jump to label if not equal
                    if instr[1] not in self.labels.keys(): # ensure first operand is label
                        raise Exception("Invalid label for jump at line " + str(i) + ": " + aux)

                    self.memory[ipc] = 0xEA
                    self.memory[ipc + 1] = self.labels[instr[1]]["idx"]

                    ipc += 2
                    
                case "jna": # jump to label if not above
                    if instr[1] not in self.labels.keys(): # ensure first operand is label
                        raise Exception("Invalid label for jump at line " + str(i) + ": " + aux)

                    self.memory[ipc] = 0xEB
                    self.memory[ipc + 1] = self.labels[instr[1]]["idx"]

                    ipc += 2
                    
                case "jnb": # jump to label if not below
                    if instr[1] not in self.labels.keys(): # ensure first operand is label
                        raise Exception("Invalid label for jump at line " + str(i) + ": " + aux)

                    self.memory[ipc] = 0xEC
                    self.memory[ipc + 1] = self.labels[instr[1]]["idx"]

                    ipc += 2
                    
                case "lea": # load effective address, loads address of variable (second operand) into register (first operand)
                    vals = instr[1].split(",")
                    if vals[0] not in self.register.keys(): # ensure first operand is registry
                        raise Exception("First operand not register in line " + str(i) + ": " + aux)
                    if vals[1] not in self.vars.keys(): # ensure second operand is variable
                        raise Exception("Second operand not variable in line " + str(i) + ": " + aux)

                    self.memory[ipc] = 0xED
                    self.memory[ipc + 1] = list(self.register.keys()).index(vals[0])
                    self.memory[ipc + 2] = list(self.vars.keys()).index(vals[1])

                    ipc += 3

                case "int": # interrupt, makes syscalls
                    if any(c.isalpha() for c in instr[1]): # ensure interrupt code doesn't contain letters
                        raise Exception("Invalid literal in line" + str(i) + ": " + aux)
                    if int(instr[1]) > 3: # ensure interrupt code is implemented
                        raise Exception("Invalid interrupt in line" + str(i) + ": " + aux)

                    self.memory[ipc] = 0xEE
                    self.memory[ipc + 1] = int(instr[1])

                    ipc += 2

                case "push": # push value onto stack
                    if instr[1] not in self.register.keys() and instr[1] not in self.vars.keys(): # ensure first operand is registry or variable
                        raise Exception("Operand not register or variable in line" + str(i) + ": " + aux)

                    self.memory[ipc] = 0xEF

                    if instr[1] in self.register.keys():
                        self.memory[ipc + 1] = list(self.register.keys()).index(instr[1])
                    else:
                        if self.vars[instr[1]]["type"] == "int":
                            self.memory[ipc + 1] = list(self.vars.keys()).index(instr[1]) + 0x20
                        else:
                            raise Exception("Cannot push strings/arrays. Line " + str(i) + ": " + aux)

                    ipc += 2

                case "pop": # pop value from stack
                    if instr[1] not in self.register.keys(): # ensure first operand is registry
                        raise Exception("Operand not register in line" + str(i) + ": " + aux)

                    self.memory[ipc] = 0xF0
                    self.memory[ipc + 1] = list(self.register.keys()).index(instr[1])

                    ipc += 2

                case "lodb": # load byte; first operand is registry and has the address of where to load; second operand is registry/variable/immediate and indicates the value to be loaded
                    vals = instr[1].split(",")
                    if vals[0] not in self.register.keys(): # ensure first operand is registry 
                        raise Exception("Invalid operand in line " + str(i) + ": " + aux)
                    if '"' in vals[1]: # ensure no string literals passed as second argument
                        raise Exception("Cannot use lodb with string literals. Line  " + str(i) + ": " + aux)
                    if any(c.isalpha() for c in vals[1]) and vals[1] not in self.register.keys() and vals[1] not in self.vars.keys(): # ensure that int passed as second argument doesn't contain letter
                        raise Exception("Invalid literal in line" + str(i) + ": " + aux)

                    self.memory[ipc] = 0xF1
                    self.memory[ipc + 1] = list(self.register.keys()).index(vals[0])

                    if vals[1] in self.register.keys():
                        self.memory[ipc + 2] = 'r' # hack, used to denote register
                        self.memory[ipc + 3] = list(self.register.keys()).index(vals[1])
                    elif vals[1] in self.vars.keys():
                        if self.vars[vals[1]]["type"] != "int":
                            raise Exception("Cannot use lodb on string/array literals. Line  " + str(i) + ": " + aux)
                        idx = self.vars[vals[1]]["idx"]
                        b = [self.memory[idx], self.memory[idx + 1]]
                        val = int.from_bytes(bytes(b), byteorder='little')
                        if val > 0xFF:
                            raise Exception("Attempt to load int bigger than 255 on line " + str(i) + ": " + aux)
                        self.memory[ipc + 2] = val
                        self.memory[ipc + 3] = 0
                    else:
                        if int(vals[1]) > 0xFF:
                            raise Exception("Max int value is 255 on line " + str(i) + ": " + aux)
                        b = bytearray(int(vals[1]).to_bytes(2, "little"))
                        self.memory[ipc + 2] = b[0]
                        self.memory[ipc + 3] = b[1]

                    ipc += 4

                case "stob": # store byte; first operand is registry and has the address of from where to store; second operand is registry and indicates where to store
                    vals = instr[1].split(",")
                    if vals[0] not in self.register.keys(): # ensure first operand is registry 
                        raise Exception("Invalid operand in line " + str(i) + ": " + aux)
                    if '"' in vals[1]: # ensure no string literals passed as second argument
                        raise Exception("Cannot use stob with string literals. Line  " + str(i) + ": " + aux)
                    if vals[1] not in self.register.keys() and vals[1] not in self.vars.keys(): # ensure second argument is a register or variable
                        raise Exception("Invalid literal in line" + str(i) + ": " + aux)

                    self.memory[ipc] = 0xF2
                    self.memory[ipc + 1] = list(self.register.keys()).index(vals[0])
                    self.memory[ipc + 2] = list(self.register.keys()).index(vals[1])

                    ipc += 3
            i += 1
            aux = lines[i].strip().strip("\n")
        return ipc


    def interpret(self, program, stop):
        initIP = self.ip
        for x in self.vars.keys():
            print(x + "=", end="")
            if self.vars[x]["type"] == "str":
                i = self.vars[x]["idx"]
                while self.memory[i] != 0:
                    print(self.memory[i], end="")
                    i += 1
            elif self.vars[x]["type"] == "int":
                i = self.vars[x]["idx"]
                val = int.from_bytes(bytes([self.memory[i], self.memory[i + 1]]), byteorder='little')
                print(val, end="")
            else:
                length = self.vars[x]["len"]
                i = self.vars[x]["idx"]
                print("[", end=" ")
                for j in range(length):
                    print(self.memory[i], end=" ")
                print("]", end="")
            print(",", end="")
        print("")
        l = list(self.register.keys())
        for i in range(len(l)):
            print(l[i] + "=" + str(self.register[l[i]]), end=",")
        print("rip=" + str(self.ip), end=",")
        print("EFLAGS=" + str(self.eflags))
        print("STACK=" + str(self.stack[self.register["rbp"]:self.register["rsp"]]))
        while self.ip < stop:
            instr = self.memory[self.ip]
            if not 0xE0 <= instr <= 0xF2:
                raise Exception("Invalid opcode " + str(instr))
            match instr:
                case 0xE0: # mov
                    op1 = self.memory[self.ip + 1]

                    if op1 < 0x20:
                        if isinstance(self.memory[self.ip + 2], str):
                            self.register[list(self.register.keys())[op1]] = self.register[list(self.register.keys())[self.memory[self.ip + 3]]]
                        else:
                            self.register[list(self.register.keys())[op1]] = int.from_bytes(bytes([self.memory[self.ip + 2], self.memory[self.ip + 3]]), byteorder='little')
                    else:
                        op1 -= 0x20
                        idx = self.vars[list(self.vars.keys())[op1]]["idx"]
                        if isinstance(self.memory[self.ip + 2], str):
                            val = self.register[list(self.register.keys())[self.memory[self.ip + 3]]]
                            val = val.to_bytes(2, "little")
                            self.memory[idx] = val[0]
                            self.memory[idx + 1] = val[1]
                        else:
                            self.memory[idx] = self.memory[self.ip + 2]
                            self.memory[idx + 1] = self.memory[self.ip + 3]

                    self.ip += 4

                case 0xE1: # add
                    op1 = self.memory[self.ip + 1]
                    
                    if op1 < 0x20:
                        op2 = 0
                        if isinstance(self.memory[self.ip + 2], str):
                            op2 = self.register[list(self.register.keys())[self.memory[self.ip + 3]]]
                        else:
                            op2 = int.from_bytes(bytes([self.memory[self.ip + 2], self.memory[self.ip + 3]]), byteorder='little')
                        if self.register[list(self.register.keys())[op1]] + op2 > 0xFFFF:
                            print("[*] Addition overflowed")
                        self.register[list(self.register.keys())[op1]] += op2
                        self.register[list(self.register.keys())[op1]] %= 0x10000
                    else:
                        op1 -= 0x20
                        idx = self.vars[list(self.vars.keys())[op1]]["idx"]
                        val_mem = int.from_bytes(bytes([self.memory[idx], self.memory[idx + 1]]), byteorder='little')
                        op2 = 0
                        if isinstance(self.memory[self.ip + 2], str):
                            op2 = self.register[list(self.register.keys())[self.memory[self.ip + 3]]]
                        else:
                            op2 = int.from_bytes(bytes([self.memory[self.ip + 2], self.memory[self.ip + 3]]), byteorder='little')
                        res = op2 + val_mem
                        if res > 0xFFFF:
                            print("[*] Addition overflowed")
                        res %= 0x10000
                        res = res.to_bytes(2, "little")
                        self.memory[idx] = res[0]
                        self.memory[idx + 1] = res[1]

                    self.ip += 4

                case 0xE2: # sub
                    op1 = self.memory[self.ip + 1]

                    if op1 < 0x20:
                        op2 = 0
                        if isinstance(self.memory[self.ip + 2], str):
                            op2 = self.register[list(self.register.keys())[self.memory[self.ip + 3]]]
                        else:
                            op2 = int.from_bytes(bytes([self.memory[self.ip + 2], self.memory[self.ip + 3]]), byteorder='little')
                        if self.register[list(self.register.keys())[op1]] - op2 < 0:
                            print("[*] Subtraction underflowed")
                            res = self.register[list(self.register.keys())[op1]] - op2
                            self.register[list(self.register.keys())[op1]] = 0x10000 + res
                        else:
                            self.register[list(self.register.keys())[op1]] -= op2
                    else:
                        op1 -= 0x20
                        idx = self.vars[list(self.vars.keys())[op1]]["idx"]
                        val_mem = int.from_bytes(bytes([self.memory[idx], self.memory[idx + 1]]), byteorder='little')
                        op2 = 0
                        if isinstance(self.memory[self.ip + 2], str):
                            op2 = self.register[list(self.register.keys())[self.memory[self.ip + 3]]]
                        else:
                            op2 = int.from_bytes(bytes([self.memory[self.ip + 2], self.memory[self.ip + 3]]), byteorder='little')
                        res = val_mem - op2
                        if res < 0:
                            print("[*] Subtraction underflowed")
                            res = 0x10000 - op2
                            res = res.to_bytes(2, "little")
                            self.memory[idx] = res[0]
                            self.memory[idx + 1] = res[1]
                        else:
                            res = res.to_bytes(2, "little")
                            self.memory[idx] = res[0]
                            self.memory[idx + 1] = res[1]

                    self.ip += 4
                    
                case 0xE3: # cmp
                    op1 = self.memory[self.ip + 1]

                    if op1 < 0x20:
                        op2 = 0
                        if isinstance(self.memory[self.ip + 2], str):
                            op2 = self.register[list(self.register.keys())[self.memory[self.ip + 3]]]
                        else:
                            op2 = int.from_bytes(bytes([self.memory[self.ip + 2], self.memory[self.ip + 3]]), byteorder='little')
                        res = self.register[list(self.register.keys())[op1]] - op2
                    else:
                        op2 = 0
                        if isinstance(self.memory[self.ip + 2], str):
                            op2 = self.register[list(self.register.keys())[self.memory[self.ip + 3]]]
                        else:
                            op2 = int.from_bytes(bytes([self.memory[self.ip + 2], self.memory[self.ip + 3]]), byteorder='little')
                        res = self.vars[list(self.vars.keys())[op1]] - op2
                    if res == 0:
                        self.eflags[1] = 1
                    elif res < 0:
                        self.eflags[0] = 1
                    else:
                        self.eflags = [0, 0]

                    self.ip += 4

                case 0xE4: # inc
                    op1 = self.memory[self.ip + 1]
                    if op1 < 0x20:
                        op2 = 1
                        if self.register[list(self.register.keys())[op1]] + op2 > 0xFFFF:
                            print("[*] Addition overflowed")
                        self.register[list(self.register.keys())[op1]] += op2
                        self.register[list(self.register.keys())[op1]] %= 0x10000
                    else:
                        op1 -= 0x20
                        idx = self.vars[list(self.vars.keys())[op1]]["idx"]
                        val_mem = int.from_bytes(bytes([self.memory[idx], self.memory[idx + 1]]), byteorder='little')
                        op2 = 1
                        res = op2 + val_mem
                        if res > 0xFFFF:
                            print("[*] Addition overflowed")
                        res %= 0x10000
                        res = res.to_bytes(2, "little")
                        self.memory[idx] = res[0]
                        self.memory[idx + 1] = res[1]

                    self.ip += 2

                case 0xE5: # dec
                    op1 = self.memory[self.ip + 1]

                    if op1 < 0x20:
                        op2 = 1
                        if self.register[list(self.register.keys())[op1]] - op2 < 0:
                            print("[*] Subtraction underflowed")
                            res = self.register[list(self.register.keys())[op1]] - op2
                            self.register[list(self.register.keys())[op1]] = 0x10000 + res
                        else:
                            self.register[list(self.register.keys())[op1]] -= op2
                    else:
                        op1 -= 0x20
                        idx = self.vars[list(self.vars.keys())[op1]]["idx"]
                        val_mem = int.from_bytes(bytes([self.memory[idx], self.memory[idx + 1]]), byteorder='little')
                        op2 = 1
                        res = val_mem - op2
                        if res < 0:
                            print("[*] Subtraction underflowed")
                            res = 0x10000 - op2
                            res = res.to_bytes(2, "little")
                            self.memory[idx] = res[0]
                            self.memory[idx + 1] = res[1]
                        else:
                            res = res.to_bytes(2, "little")
                            self.memory[idx] = res[0]
                            self.memory[idx + 1] = res[1]

                    self.ip += 2

                case 0xE6: # jmp
                    op1 = self.memory[self.ip + 1]
                    self.ip = op1

                case 0xE7: # je
                    op1 = self.memory[self.ip + 1]
                    if self.eflags[1]: # zero flag set
                        self.ip = op1
                    else:
                        self.ip += 2

                case 0xE8: # ja
                    op1 = self.memory[self.ip + 1]
                    if self.eflags[0] == 0 and self.eflags[1] == 0: # both flags 0
                        self.ip = op1
                    else:
                        self.ip += 2

                case 0xE9: # jb
                    op1 = self.memory[self.ip + 1]
                    if self.eflags[0]: # sign flag set
                        self.ip = op1
                    else: 
                        self.ip += 2

                case 0xEA: # jne
                    op1 = self.memory[self.ip + 1]
                    if not self.eflags[1]: # zero flag not set
                        self.ip = op1
                    else:
                        self.ip += 2

                case 0xEB: # jna
                    op1 = self.memory[self.ip + 1]
                    if self.eflags[0] or self.eflags[1]: # if any of the 2 flags are set
                        self.ip = op1
                    else:
                        self.ip += 2

                case 0xEC: # jnb
                    op1 = self.memory[self.ip + 1]
                    if not self.eflags[0]: # if the sign flag is not set
                        self.ip = op1
                    else:
                        self.ip += 2

                case 0xED: # lea
                    op1 = self.memory[self.ip + 1]
                    op2 = self.memory[self.ip + 2]
                    self.register[list(self.register.keys())[op1]] = self.vars[list(self.vars.keys())[op2]]["idx"]
                    self.ip += 3

                case 0xEE: # int
                    op1 = self.memory[self.ip + 1]
                    if op1 == 0: # read from file - file_path address in rax; buffer address in rbx; length in rcx
                        file_path = ""
                        idx = self.register["rax"]
                        while self.memory[idx] != 0:
                            file_path += self.memory[idx]
                            idx += 1

                        buf = self.register["rbx"]
                        found = False
                        l = 0
                        for x in self.vars.keys():
                            if self.vars[x]["idx"] == buf:
                                if self.vars[x]["type"] != "arr":
                                    raise Exception("Cannot read into a non-array buffer!")
                                found = True
                                l = self.vars[x]["len"]
                                break

                        length = self.register["rcx"]
                        if not found:
                            raise Exception("Attempting to read into an unexistent buffer!")
                        if l < length:
                            raise Exception("Attempting to read more bytes than the buffer holds!")

                        try:
                            aux_buf = []
                            with open(file_path, "rb") as f:
                                aux_buf = f.read(length)
                            for x in aux_buf:
                                self.memory[buf] = x
                                buf += 1
                        except Exception:
                            raise Exception("File not found!")

                    elif op1 == 1: # write to file - file_path address in rax; buffer address in rbx; length in rcx
                        file_path = ""
                        idx = self.register["rax"]
                        while self.memory[idx] != 0:
                            file_path += self.memory[idx]
                            idx += 1

                        buf = self.register["rbx"]
                        var = ""
                        for x in self.vars.keys():
                            if self.vars[x]["idx"] == buf:
                                var = x
                                break

                        if var == "":
                            raise Exception("Attempting to write from an unexistent buffer")
                        length = self.register["rcx"]
                        buf = []
                        if self.vars[var]["type"] == "arr":
                            if self.vars[var]["len"] < length:
                                raise Exception("Attempting to write more bytes than the buffer holds!")
                            idx = self.vars[var]["idx"]
                            for i in range(length):
                                buf.append(self.memory[idx])
                                idx += 1
                        elif self.vars[var]["type"] == "str":
                            l = 0
                            idx = self.vars[var]["idx"]
                            while self.memory[idx] != 0:
                                buf.append(ord(self.memory[idx]))
                                idx += 1
                                l += 1
                            if l < length:
                                raise Exception("Attempting to write more bytes than the buffer holds!")
                        else:
                            idx = self.vars[var]["idx"]
                            aux = bytes([self.memory[idx], self.memory[idx + 1]])
                            aux = int.from_bytes(aux, byteorder='little')
                            buf = aux.to_bytes(2, "big")

                        try:
                            with open(file_path, "wb") as f:
                                f.write(buf)
                        except Exception:
                            raise Exception("File not found!")

                    elif op1 == 2: # read from stdin - buffer address in rax; length in rcx
                        buf = self.register["rax"]
                        found = False
                        l = 0
                        for x in self.vars.keys():
                            if self.vars[x]["idx"] == buf:
                                if self.vars[x]["type"] != "arr":
                                    raise Exception("Cannot read into a non-array buffer!")
                                found = True
                                l = self.vars[x]["len"]
                                break

                        length = self.register["rcx"]
                        if not found:
                            raise Exception("Attempting to read into an unexistent buffer!")
                        if l < length:
                            raise Exception("Attempting to read more bytes than the buffer holds!")

                        try:
                            aux_buf = []
                            k = 0
                            while k != length:
                                aux_buf.append(int(input("")))
                                k += 1
                            for x in aux_buf:
                                self.memory[buf] = x
                                buf += 1
                        except Exception as e:
                            raise Exception(e)
                    else: # write to stdin - buffer address in rax; length in rcx
                        buf = self.register["rax"]
                        var = ""
                        for x in self.vars.keys():
                            if self.vars[x]["idx"] == buf:
                                var = x
                                break

                        if var == "":
                            raise Exception("Attempting to write from an unexistent buffer")
                        length = self.register["rcx"]
                        buf = []
                        if self.vars[var]["type"] == "arr":
                            if self.vars[var]["len"] < length:
                                raise Exception("Attempting to write more bytes than the buffer holds!")
                            idx = self.vars[var]["idx"]
                            for i in range(length):
                                buf.append(self.memory[idx])
                                idx += 1
                        elif self.vars[var]["type"] == "str":
                            l = 0
                            idx = self.vars[var]["idx"]
                            while self.memory[idx] != 0:
                                buf.append(ord(self.memory[idx]))
                                idx += 1
                                l += 1
                            if l < length:
                                raise Exception("Attempting to write more bytes than the buffer holds!")
                        else:
                            idx = self.vars[var]["idx"]
                            aux = bytes([self.memory[idx], self.memory[idx + 1]])
                            aux = int.from_bytes(aux, byteorder='little')
                            buf = aux.to_bytes(2, "big")

                        try:
                            if self.vars[var]["type"] != "str":
                                print("")
                                print(buf)
                                print("")
                            else:
                                strr = ""
                                for x in buf:
                                    strr += chr(x)
                                print("")
                                print(strr[:length])
                                print("")
                        except Exception as e:
                            raise Exception(e)
                    self.ip += 2
                case 0xEF: # push
                    op1 = self.memory[self.ip + 1]
                    if op1 < 0x20:
                        val = self.register[list(self.register.keys())[op1]].to_bytes(2, "little")
                    else:
                        val = [self.memory[list(self.vars.keys())[op1]["idx"]], self.memory[list(self.vars.keys())[op1]["idx"] + 1]]
                    self.stack[self.register["rsp"]] = val[0]
                    self.stack[self.register["rsp"] + 1] = val[1]
                    self.register["rsp"] += 2
                    self.ip += 2

                case 0xF0: # pop
                    op1 = self.memory[self.ip + 1]
                    res = int.from_bytes(bytes([self.stack[self.register["rsp"] - 2], self.stack[self.register["rsp"] - 1]]), byteorder='little')
                    self.register[list(self.register.keys())[op1]] = res
                    self.register["rsp"] -= 2
                    self.ip += 2

                case 0xF1: # lodb
                    op1 = self.memory[self.ip + 1]
                    reg = self.register[list(self.register.keys())[op1]]
                    val = self.memory[self.ip + 2]
                    if isinstance(val, str):
                        val = self.register[list(self.register.keys())[self.memory[self.ip + 3]]]
                    else:
                        val = int.from_bytes(bytes([self.memory[self.ip + 2], self.memory[self.ip + 3]]), byteorder='little')
                    if reg >= self.ip:
                        raise Exception("Attempting to read from program's memory!")
                    self.memory[reg] = val
                    self.ip += 4

                case 0xF2: # stob
                    op1 = self.memory[self.ip + 1]
                    reg = self.register[list(self.register.keys())[op1]]
                    regStore = list(self.register.keys())[self.memory[self.ip + 2]]
                    if reg >= self.ip:
                        raise Exception("Attempting to read from program's memory!")
                    self.register[regStore] = self.memory[reg]
                    self.ip += 3

            for x in self.vars.keys():
                print(x + "=", end="")
                if self.vars[x]["type"] == "str":
                    i = self.vars[x]["idx"]
                    while self.memory[i] != 0:
                        print(self.memory[i], end="")
                        i += 1
                elif self.vars[x]["type"] == "int":
                    i = self.vars[x]["idx"]
                    val = int.from_bytes(bytes([self.memory[i], self.memory[i + 1]]), byteorder='little')
                    print(val, end="")
                else:
                    length = self.vars[x]["len"]
                    i = self.vars[x]["idx"]
                    print("[", end=" ")
                    for j in range(length):
                        print(self.memory[i], end=" ")
                    print("]", end="")
                print(",", end="")
            print("")
            l = list(self.register.keys())
            for i in range(len(l)):
                print(l[i] + "=" + str(self.register[l[i]]), end=",")
            print("rip=" + str(self.ip), end=",")
            print("EFLAGS=" + str(self.eflags))
            print("STACK=" + str(self.stack[self.register["rbp"]:self.register["rsp"]]))

    def run(self, program):
        self.loadData(program)
        stop = self.loadProgram(program)
        self.interpret(program, stop)



if __name__ == "__main__":
    p = Program()
    # put program as parameter to the run function
    # data section begins with ".DATA:" followed by newline, then variable declarations of the type "varName varValue", where the variable value type can be string denoted by the use of "" or int or array, denoted by [arrayLength], then data section should end with "END DATA" on a new line
    # code section begins with ".CODE:" followed by newline, then instructions without spaces between the operands, just a comma (but a space after the instruction), and should end with "END CODE" on a newline
    # labels are denoted by labelName:, no whitespaces allowed
    # variables are loaded at the beginning of memory, and the instructions follow immediately after
    p.run('''.DATA:
test "C:\\Users\\alex\\Desktop\\a.txt"
buf [14]
END DATA
.CODE:
lea rax,test
lea rbx,buf
mov rcx,14
int 0
lea rax,buf
mov rcx,14
int 3
mov rcx,96
mov rdx,14
LOOP:
lodb rax,rcx
inc rax
dec rdx
cmp rdx,0
ja LOOP
lea rax,buf
mov rcx,14
int 3
END CODE
''') # modification of the loading from file code, where I use the load byte instruction to modify the buffer to all 96s
    #print(p.memory[:500])

""" # read buffer from file and write it to the screen (will appear as a buffer even if a string was read)
.DATA:
test "C:\\Users\\adi\\Desktop\\a.txt"
buf [14]
END DATA
.CODE:
lea rax,test
lea rbx,buf
mov rcx,14
int 0
lea rax,buf
int 3
END CODE
"""


""" # example if statement: rax = 10; rbx = 20; if (rbx > rax) rax--; else rax++; rbx = rax;
.CODE:
mov rax,10
mov rbx,20
cmp rbx,rax
ja ABOVE
inc rax
jmp AFTER
ABOVE:
dec rax
AFTER:
mov rbx,rax
END CODE
"""

""" # example loop: rcx = 10; while (rcx > 0) rcx--;   <====>  for(rcx = 10; rcx > 0; rcx--) ;
.CODE:
mov rcx,10
LOOP:
dec rcx
cmp rcx,0
ja LOOP
END CODE
"""


""" # example stack usage
.DATA:
test "C:\\Users\\adi\\Desktop\\test.txt"
buf [14]
END DATA
.CODE:
mov rax,1
mov rbx,2
push rax # rax is really needed for something else => STACK = [raxStack]
push rbx # rbx is really needed for something else => STACK = [raxStack, rbxStack]
lea rax,test
lea rbx,buf
mov rcx,14
int 0
pop rbx # get back the value of rbx (pops last element); STACK = [raxStack, rbxStack] => pop last element => rbx = rbxStack
pop rax # get back the value of rax (pops last element); STACK = [raxStack] => pop last element => rax = raxStack
"""


""" # example usage for printing string to screen - rax has the address of the string, rcx the length, and the interrupt code is 3
.DATA:
buf "test_string"
END DATA
.CODE:
lea rax,buf
mov rcx,11
int 3
END CODE
"""