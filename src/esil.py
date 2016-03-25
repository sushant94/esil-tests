import r2pipe
import json

class Emulator:
    ''' Initialize r2pipe'''
    def __init__(self, binfile, logfile=None):
        self.r2 = r2pipe.open(binfile)
        self.r2.cmd("aaa")
        self.r2.cmd("e asm.esil = true")
        self.r2.cmd("e scr.color = false")
        self.r2.cmd("e io.cache = true")
        self.r2.cmd("aei")
        self.r2.cmd("aeip")
        self.stats = {}
        self.binfile = binfile
        self.logfile = logfile
        self.logs = []
        self.prev_state = {}
        self.last_emulated = {}

    def init_memory(self, addr):
        self.r2.cmd("aeim {} 0x10000 Stack".format(addr))

    def step(self):
        self.prev_state = self.registers()
        inst = self.instruction()
        if len(inst) == 0:
            self.last_emulated = {
                    "opcode": "invalid",
                    "esil": "invalid",
                    "offset": "invalid"
                    }
        elif(inst[0]["type"] == "invalid"):
            self.last_emulated = {
                    "opcode": "invalid",
                    "esil": "invalid",
                    "offset": hex(inst[0]["offset"])
                    }
        else:
            self.last_emulated = {
                    "opcode": inst[0]["opcode"],
                    "esil": inst[0]["esil"],
                    "offset": hex(inst[0]["offset"])
                    }
        self.r2.cmd("aes")

    # Log results
    def log(self, original, event, diff):
        info = {}
        # For now, do not log invalid opcodes
        if("opcode" in self.last_emulated and self.last_emulated["opcode"] == "invalid"):
            return
        info["instruction"] = self.last_emulated
        info["event"] = event
        info["diff"] = diff
        self.logs.append(info)

    def registers(self):
        return json.loads(self.r2.cmd("arj"))

    def instruction(self):
        return json.loads(self.r2.cmd("pdj 1 @ `ar rip`"))

    # In case of a mismatch, all further instructions are also bound to be
    # incorrect. Instead we set registers to correct results and continue.
    def set_register(self, key, value):
        s = self.r2.cmd("aer {} = {}".format(key, value))

    def entry(self):
        return self.r2.cmd("s").strip()

    def exit(self):
        f = open(self.logfile, "w")
        f.write(json.dumps(self.logs))
        f.close()
        self.r2.cmd("quit")
        self.r2 = None

