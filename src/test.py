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

Behavior when ESIL instruction is unimplemented:
    If an ESIL instruction is unimplemented, then we record this as a "TODO"
    rather than a mismatch.

Additionally, the ESIL emulator also keeps track of various stats such as
number of TODOs encountered, number of instructions emulated, most common
missing instructions etc. These statistics can help us decide what to focus on
in ESIL next.

Error reporting:
    - To make the Error logs generated easily accessible, we upload the json
    logs to a gist.
    - Errors are automatically reported by raising an issue on the repository
    with the link to the error logs.
    - These are done as a part of the cleanup step.
'''

import esil
from os import listdir
from os.path import isfile, join
from subprocess import check_output
import json
import struct

def init_gdb(binfile, bp):
    # Create a command to execute this script within gdb.
    cmd = "sudo gdb --eval-command 'b *{}' --command src/tracer.py --args {}".format(bp, binfile)
    cmd = cmd.replace('\\', '\\\\').replace('`', '\\`').replace('"', '\\"')
    print cmd
    check_output(cmd, shell=True)

def compare_states(run, emu):
    diff = {}
    for (k, v) in run.iteritems():
        if k not in emu:
            continue
        if emu[k] != struct.unpack('>q', ("%x" % v).rjust(16, '0').decode('hex'))[0]:
            diff[k] = { "esil": hex(emu[k]), "gdb": hex(v) }
    return diff

# Perform some after test actions, such as automatically opening issues on
# github and writing out error logs to gist, etc.
def cleanup():
    print "Done."

if __name__ == "__main__":
    # TODO: Command line args
    path = "./bin/"
    log_path = "./log/"
    bins = [f for f in listdir(path) if isfile(join(path, f))]
    print "Starting Tests."
    for b in bins:
        # Create trace file
        logfile = join(log_path, b + ".log")

        # Create a new logfile for ESIL emulation
        emu = esil.Emulator(path + b, logfile)
        entry0 = emu.entry()

        init_gdb(path + b, entry0)

        # Load the JSON with the tracer results
        logfile = join(log_path + "trace_log")
        logfile = open(logfile, "r")
        results = json.load(logfile)
        logfile.close()

        print "Loaded execution logs"
        prev_state = {}
        #emu.step()
        for r in results:
            diff = compare_states(r["registers"], emu.registers())
            if len(diff) > 0:
                # This means there is a potential bug in our emulation. Log this, reset
                # registers to correct values and continue emulation.
                for (k, v) in diff.iteritems():
                    if k not in emu.prev_state: continue
                    diff[k]["esil_old"] = hex(emu.prev_state[k])
                    diff[k]["gdb_old"] = hex(prev_state[k])
                emu.log(r, "Mismatch", diff)
                for (k, v) in diff.iteritems():
                    emu.set_register(k, v["gdb"])
            emu.step()
            prev_state = r["registers"]
        emu.exit()
        cleanup()

