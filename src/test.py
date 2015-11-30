'''
This module initializes and runs all the tests. Here is a basic description of
the system. All binaries that are to be tested are placed inside bin/
directory. The system automatically picks up binaries to run tests against
them.

- init_gdb initializes and runs a binary inside gdb. It achieves this by
  running src/tracer.py with the binary file as arguments. This creates a
  trace of the entire run and stores it under log/
- esil module contains the ESIL emulator against which a run is compared.

This test module runs the esil emulator comparing the values of registers
after every instruction. If there is a mismatch, this error is logged in a
separate file and registers are set to correct values (as taken from the gdb
log) in order to ensure that the error does not continue along the execution.
Otherwise, all instruction after the first error are bound to produce
different results and hence would be flagged incorrect by the tester.

The comparison is performed by compare_states that compares the ESIL emulation
against the gdb register states.
'''

import esil
from os import listdir
from os.path import isfile, join
from subprocess import check_output
import json

def init_gdb(binfile):
    # Create a command to execute this script within gdb.
    cmd = 'gdb --command src/tracer.py --args {}'.format(binfile)
    cmd = cmd.replace('\\', '\\\\').replace('`', '\\`').replace('"', '\\"')
    print cmd
    check_output(cmd, shell=True)

def compare_states(run, emu):
    diff = {}
    for (k, v) in run.iteritems():
        if k not in emu:
            continue
        if emu[k] != v:
            diff[k] = { "esil": hex(emu[k]), "gdb": hex(v) }
    return diff

# Perform some after test actions, such as automatically opening issues on
# github and writing out error logs to gist, etc.
def cleanup():
    print "Done."

if __name__ == "__main__":
    # TODO: Command line args
    path = "bin/"
    log_path = "log/"
    bins = [f for f in listdir(path) if isfile(join(path, f))]
    for b in bins:
        # Create trace file
        logfile = join(log_path + "trace_log")
        init_gdb(b)
        # Load the JSON with the tracer results
        logfile = open(logfile, "r")
        results = json.load(logfile)
        logfile.close()
        # Create a new logfile for ESIL emulation
        logfile = join(log_path, b + ".log")
        # Run the bin inside the emulator
        emu = esil.Emulator(path + b, logfile)
        for r in results:
            diff = compare_states(r["registers"], emu.registers())
            if len(diff) > 0:
                # This means there is a potential bug in our emulation. Log this, reset
                # registers to correct values and continue emulation.
                emu.log(r, "Mismatch", diff)
                for (k, v) in diff.iteritems():
                    emu.set_register(k, v["gdb"])
            emu.step()
        emu.exit()
        cleanup()

