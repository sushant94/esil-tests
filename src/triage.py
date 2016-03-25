'''
This module takes a logfile generated from this tracer and helps in some
analysis.

Some basic functions that it currently supports are:
    - Basic Statistics
    - Most frequently mismatched evaluations

TODO:
    - Blacklist / Skip offsets.
    - Template full bug-reporting. Github API to automatically open this bug.
    - Generate testcase file for use in r2-regressions automatically.
'''

import sys
import json

def analyze_freq(h):
    freq = {}
    h.pop(0)
    for k in h:
        opcode = k["instruction"]["opcode"].split(" ")[0]
        if opcode not in freq:
            freq[opcode] = []
        freq[opcode].append(k)
    return freq

def pretty_print(r):
    print "Instruction: " + r["instruction"]["opcode"]
    print "ESIL: " + r["instruction"]["esil"]
    print "Offset: " + r["instruction"]["offset"]
    print "+" + "-"*74 + "+"
    print "| REGISTER".ljust(25) + "| GDB".ljust(25) + "| ESIL".ljust(25) + "|"
    print "+" + "-"*74 + "+"
    for d in r["diff"]:
        print "| {} | {} | {} |".format(d.ljust(22), r["diff"][d]["gdb"].ljust(22), r["diff"][d]["esil"].ljust(22))
    print "+" + "-"*74 + "+"

def get_next(i, freq):
    it = freq.items()
    it.sort(key=lambda item: (len(item[1]), item[1]), reverse=True)
    return it[i][1]

if __name__ == "__main__":
    logfile = sys.argv[1]
    f = open(logfile, 'r')
    h = json.load(f)
    print "Analyzing ...."
    freq = analyze_freq(h)

    print '''
             [N] Next occurance of mismatch of same instruction
             [S] Next Mismatched instruction (sorted based on frequency)
             [Q] Quit
           '''
    option = "S"

    fiter = -1
    iiter = -1
    cur_l = []

    while True:
        if option == "S":
            fiter += 1
            cur_l = get_next(fiter, freq)
            print "Number of mismatches: {}".format(len(cur_l))
            iiter = -1
        elif option == "N" or option == "":
            iiter += 1
            if iiter < len(cur_l):
                pretty_print(cur_l[iiter])
            else:
                print "No more to display."
        else:
            break
        print "Command: ",
        option = raw_input().strip()
        print
