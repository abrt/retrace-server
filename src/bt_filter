#!/usr/bin/python
# 
#  Copyright (C) 2009 Flavio Leitner <fleitner@redhat.com>
#  
#  This copyrighted material is made available to anyone wishing to use,
#  modify, copy, or redistribute it subject to the terms and conditions
#  of the GNU General Public License, either version 2 of the License, or
#  (at your option) any later version
# 
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
# 
# 
#  Description:
#    The vmcore usually shows many processes with the same backtrace.
#    This program groups similar backtraces reducing the amount of 
#    data to be reviewed. 
# 
#  Author: Flavio Leitner <fleitner@redhat.com>
#
#  ChangeLog:
#   * Wed Nov 4 - Flavio Leitner <fleitner@redhat.com>
#     PID list report organized to print pids grouped by command
#     (thanks to Fabio Olive for the suggestion)
#
# Example of usage:
#
#  crash> foreach bt > bt.all
#  $ wget http://people.redhat.com/~fleitner/bt_filter/bt_filter.py
#  $ chmod +x bt_filter.py
#  $ bt_filter.py bt.all
# 


import os
import sys
import fileinput
if sys.version_info[:2] >= (2,5):
    from hashlib import sha1 as sha
else:
    from sha import sha



version = '0.7'

debug = 0

BT_BEGINNING = 1
BT_ENDING = 2

#PID: 373    TASK: d5874550  CPU: 7   COMMAND: "BBCU"
def backtrace_is_starting(line):
    ret = False
    if line.find('PID:') == 0 and line.find('CPU:') > 0:
        ret = True

    if debug > 1:
        print "backtrace_is_starting: %d" % ret
    return ret


def backtrace_is_ending(line):
    ret = False
    if len(line) <= 2:
        ret = True
    if debug > 1:
        print "backtrace_is_ending: %d" % ret
    return ret


def backtrace_is_frame(line):
    ret = True
    if line.find('#') < 0:
        ret = False

    if debug > 1:
        print "backtrace_is_frame: %d" % ret
    return ret


#PID: 373    TASK: d5874550  CPU: 7   COMMAND: "BBCU"
def backtrace_get_proc_info(line):
    end = line.find('TASK:')
    start = len('PID:')
    pid = int(line[start:end])
    start = line.find('COMMAND:')  + len('COMMAND: ')
    cmd = line[start:-1]
    cmd = cmd.strip('"')
    ret = (cmd, pid)
    if debug > 1:
        print "backtrace_get_proc_info: %s[%d]" % (ret)

    return ret
    


def backtrace_calc_hash(proc_backtrace):
    hash = sha(''.join(proc_backtrace))
    hash_digest = hash.hexdigest()
    if debug > 1:
        print "backtrace_calc_hash: %s" % hash_digest
    return hash_digest
    


#0 [e041ed40] schedule at c06076a4
def backtrace_clear_frame(line):
    start = line.find('[')
    end = line.find(']') + 1
    frame = line[:start] + line[end:]
    frame = frame.strip()
    if debug > 1:
        print "backtrace_clear_frame: %s" % frame

    return frame


def backtrace_file_parser(input, bt_hash, bt_proc):
    state = BT_BEGINNING
    line = input.readline()
    while line:
        if debug > 0:
            print "Line: %s" % line
        if state == BT_ENDING:
            if backtrace_is_ending(line):
                if debug > 0:
                    print "found ending: %s" % line
                state = BT_BEGINNING
                hash = backtrace_calc_hash(proc_backtrace)
                if bt_proc.has_key(hash):
                    bt_proc[hash].append( proc_info )
                else:
                    bt_proc[hash] = [ proc_info ]

                if not bt_hash.has_key(hash):
                    bt_hash[hash] = proc_backtrace

                line = input.readline()
                continue

        if state == BT_BEGINNING:
            if backtrace_is_starting(line):
                if debug > 0:
                    print "found starting: %s" % line
                state = BT_ENDING
                proc_backtrace = []
                proc_info = backtrace_get_proc_info(line)
                line = input.readline()
                continue

        if backtrace_is_frame(line):
            if debug > 0:
                print "found frame: %s" % line
            clean_bt_frame = backtrace_clear_frame(line)
            proc_backtrace.append(clean_bt_frame)

        line = input.readline()

    return



def backtrace_report(bt_hash, bt_proc):
    if debug > 2:
        print "-<>-"
        print bt_proc
        print "----"
        print bt_hash
        print "-<>-"

    for hash in bt_hash:
        print "\nBacktrace:"
        backtrace = bt_hash[hash]
        for line in backtrace:
            print "%s" % line 

        print "PID List:"
        # group all PIDs of the same command
        task_list = {}
        for task_info in bt_proc[hash]:
            if task_list.has_key(task_info[0]):
                task_list[task_info[0]].append(task_info[1])
            else:
                task_list[task_info[0]] = [task_info[1]]

        pid_output = ""
        line = ''
        tasks = task_list.keys()
        tasks.sort()
        for t in tasks:
            line = line + "  %s *%d[" % (t, len(task_list[t]))
            for pid in task_list[t]:
                line = line + "%d " % pid
            line = line[:-1] + "]\n"
            pid_output = pid_output + line
            line = ''

        print pid_output
        print "Total of %d PIDs\n" % len(bt_proc[hash])
            

def main():
    input = fileinput.input()
    if not input:
        print "Error opening input file"
        sys.exit(1)

    bt_hash = {}
    bt_proc = {}
    backtrace_file_parser(input, bt_hash, bt_proc)
    backtrace_report(bt_hash, bt_proc)
    return



if __name__ == '__main__':
    print 'version: %s\n' % version
    main()
    sys.exit(0)

# vim: ts=4 sw=4 et
