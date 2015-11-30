import r2pipe
import json

class Emulator:
    ''' Initialize r2pipe'''
    def __init__(self, binfile, logfile=None):
        self.r2 = r2pipe.open(binfile)
        self.r2.cmd("aaa")
        self.r2.cmd("e asm.esil = true")
        self.r2.cmd("e scr.color = false")
        self.stats = {}
        self.binfile = binfile
        self.logfile = logfile
        self.logs = []
        self.prev_state = {}
        self.last_emulated = {}

    def step(self):
        self.prev_state = self.registers()
        inst = self.instruction()
        self.last_emulated = {
                "opcode": inst[0]["opcode"],
                "esil": inst[0]["esil"],
                "offset": hex(inst[0]["offset"])
                }
        self.r2.cmd("aes")
        self.r2.cmd("so")

    # Log results
    def log(self, original, event, diff):
        info = {}
        info["instruction"] = self.last_emulated
        info["event"] = event
        info["diff"] = diff
        self.logs.append(info)

    def registers(self):
        return json.loads(self.r2.cmd("arj"))

    def instruction(self):
        return json.loads(self.r2.cmd("pdj 1"))

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

