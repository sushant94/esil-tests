import gdb
import json
import sys
import re


'''
Tracer runs the given binary inside a debugger (gdb) and logs register and
memory state in a standard JSON format. This is later used by the emulator to
compare ESIL emulation results vs. the run inside a debugger
'''
class Tracer:
    def __init__(self, logfile, tracked = None):
        self.stats = {}
        self.logfile = logfile
        self.tracked = tracked
        f = open(logfile, "w")
        f.close()

    def get_state(self):
        state = {}
        state["instruction"] = self.get_current_instruction()
        state["registers"] = self.get_register_states()
        return state

    def get_current_instruction(self):
        inst = gdb.execute("x/i $pc", False, True)
        inst  = re.sub("(\t| )+", " ", inst)
        inst = inst.split(':')
        return inst[1].strip()

    def get_register_states(self):
        r = {}
        registers = gdb.execute("i r", False, True)
        registers = registers.split("\n")
        pat = re.compile("( |\t)+")
        for reg in registers:
            reg = re.sub(pat, " ", reg.strip())
            reg = reg.split(" ")
            # Get only the tracked registers.
            if self.tracked is not None and reg[0] not in self.tracked:
                continue
            if len(reg) > 1:
                r[reg[0]] = int(reg[1], 16)
        return r

    def write_log(self, data):
        f = open(self.logfile, "a+")
        f.write(json.dumps(data))
        f.close()

    def log(self, event):
        gdb.events.stop.disconnect(self.log)
        r = []
        while True:
            r.append(self.get_state())
            gdb.execute("si")
        self.write_log(r)
        gdb.execute("quit")

    def run(self):
        gdb.events.exited.connect(lambda event: self.exit())
        gdb.events.stop.connect(self.log)
        gdb.execute("run")

    def exit(self):
        gdb.execute("quit")


if __name__ == "__main__":
    logfile = "log/trace_log"
    t = Tracer(logfile)
    t.run()
