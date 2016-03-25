'''
This module takes a logfile generated from this tracer and helps in some
analysis.

Some basic functions that it currently supports are:
    - Basic Statistics
    - Most frequently mismatched evaluations

TODO:
    - Blacklist / Skip offsets.
    - Template full bug-reporting. Github API to automatically open this bug.
'''

import sys
import json
import subprocess

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
    # TODO
    print "Binary: Ubuntu 14.04 /bin/ls"
    print "Instruction: " + r["instruction"]["opcode"]
    print "ESIL: " + r["instruction"]["esil"]
    print "Offset: " + r["instruction"]["offset"]
    rwd = 10
    vwd = 20
    width = rwd + 4*vwd
    #print "+" + "-"*(width-1) + "+"
    print
    print "| REGISTER".ljust(rwd) + "| GDB".ljust(2*vwd) + "| ESIL".ljust(2*vwd) + "|"
    print "|" + "-"*(rwd-1) + "|" + "-"*(2*vwd-1) + "|" + "-"*(2*vwd-1) + "|"
    for d in r["diff"]:
        gdb_s = "{} -> {}".format(r["diff"][d]["gdb_old"], r["diff"][d]["gdb"])
        esil_s = "{} -> {}".format(r["diff"][d]["esil_old"], r["diff"][d]["esil"])
        print "| {} | {} | {} |".format(d.ljust(rwd-3), gdb_s.ljust(2*vwd - 3),\
                esil_s.ljust(2*vwd - 3))
    print "|" + "-"*(rwd-1) + "|" + "-"*(2*vwd-1) + "|" + "-"*(2*vwd-1) + "|"
    print

def get_next(i, freq):
    it = freq.items()
    it.sort(key=lambda item: (len(item[1]), item[1]), reverse=True)
    return it[i][1]

def get_offset(e):
    return e["instruction"]["offset"]


def update_reports(f, arr, elem):
    # Update the reported list
    offset = get_offset(elem)
    arr.append(offset)
    f.write(offset + "\n")


if __name__ == "__main__":
    logfile = sys.argv[1]
    f = open(logfile, 'r')
    h = json.load(f)
    print "Analyzing ...."
    freq = analyze_freq(h)
    # Get offsets of mis-matches that have already been reported.
    report_f = open("reports", 'a+')
    reported = open("reports", 'r').read().split("\n")

    print '''* - Requires GHI and Authentication
             [N] Next occurance of mismatch of same instruction
             [S] Next Mismatched instruction (sorted based on frequency)
             [I] Ignore this mismatch
             [O] Open an Issue [*]
             [C] Add a comment to an existing issue [*]
             [Q] Quit
           '''
    option = "S"

    fiter = -1
    iiter = -1
    cur_l = []

    print "Total Mismatches: " + str(len(h))
    print "Reported / Ignored: " + str(len(reported))
    print

    while True:
        if option == "S":
            fiter += 1
            cur_l = get_next(fiter, freq)
            print "Number of mismatches: {}".format(len(cur_l))
            iiter = -1
        elif option == "N" or option == "":
            iiter += 1
            while iiter < len(cur_l) and get_offset(cur_l[iiter]) in reported:
                iiter += 1
                continue
            if iiter < len(cur_l):
                pretty_print(cur_l[iiter])
            else:
                print "No more to display."
        elif option == "O":
            # Opens a bug with assignee as self, and labeled as "esil" and "blocker"
            subprocess.call("ghi open --claim --label esil blocker", shell=True)
            update_reports(report_f, reported, cur_l[iiter])
            # Goto next mis-match
            iiter += 1
        elif option == "C":
            issue = raw_input().strip()
            subprocess.call("ghi comment" + issue)
            update_reports(report_f, reported, cur_l[iiter])
            iiter += 1
        elif option == "I":
            update_reports(report_f, reported, cur_l[iiter])
            iiter += 1
        else:
            report_f.close()
            break
        print "Command: ",
        option = raw_input().strip()
        print
