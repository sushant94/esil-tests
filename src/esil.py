import r2pipe
import json

class Emulator:
    ''' Initialize r2pipe'''
    def __init__(self, binfile, logfile=None):
        self.stats = {}
        self.r2 = r2pipe.open(binfile)
        self.r2.cmd("aaa")
        self.r2.cmd("e asm.esil = true")
        self.r2.cmd("e scr.color = false")
        self.binfile = binfile
        self.logfile = open(logfile, "w")
        self.logfile.write("[")

    def step(self):
        self.r2.cmd("aes")

    # Log results
    def log(self, original, event):
        info = self.instruction()
        info["event"] = event
        info["expect"] = original
        json = Json.dump(inst) + ","
        self.logfile.write(json)

    def registers(self):
        return self.r2.cmd("ar")

    def instruction(self):
        return self.r2.cmd("pdj 1")

    # In case of a mismatch, all further instructions are also bound to be
    # incorrect. Instead we set registers to correct results and continue.
    def set_register(self, key, value):
        self.r2.cmd("aer {} = {}" % (key, value))


