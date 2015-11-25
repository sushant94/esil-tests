import gdb
import json

'''
Tracer runs the given binary inside a debugger (gdb) and logs register and
memory state in a standard JSON format. This is later used by the emulator to
compare ESIL emulation results vs. the run inside a debugger
'''
class Tracer:
    def __init__(self, logfile):
        self.stats = {}
        self.logfile = open(logfile, "w")
        self.logfile.write("[")

    def run(self, bp):
        gdb.execute("b *{}" % (bp))
        gdb.events.exited.connect(lambda event: self.exit())
        gdb.stop.connect(lambda event: gdb.execute("continue"))
        while True:
            rh = {}
            registers = gdb.execute("i r")
            registers = registers.split("\n")
            for reg in registers:
                x = reg.split("\t")
                rh[x[0]] = x[1]
            self.logfile.write(Json.dump(rh))
            gdb.execute('nexti')

    def exit(self):
        self.logfile.write("]")
