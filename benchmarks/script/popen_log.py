##########################################################################
# Author: Wen
# Date:   5/19/2022
# Description: wrapper for log
##########################################################################

import sys
import os
import signal
import time
import subprocess
from threading import Timer

sub = None
cov_log = "cov.log"

if len (sys.argv) < 2:
    print ("\n*******************************************************")
    print ("python extract_log.py [command]")
    print ("\n*******************************************************\n")
    exit (0)

command   = sys.argv[1]
print ("[command]: %s" %command)


def exit_fuzz ():
    print ("\n*******************************************************")
    print ("%s execution Done! ....." %command)
    print ("\n*******************************************************\n")
    if sub != None:
        os.killpg(os.getpgid(sub.pid), signal.SIGTERM)
    exit (0)

# 24 hours
default_time = 3600*24
if len (sys.argv) == 3:
    default_time = int (sys.argv[2])
sTimer = Timer(default_time, exit_fuzz)
sTimer.start()

if os.path.exists (cov_log):
    os.remove (cov_log)

# execute the command
sub = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr = subprocess.STDOUT)

while True:
    line = sub.stdout.readline()
    if not line: break
  
    log = line.decode("utf-8").replace ("\n", "")
    if "cov:" in log:
        print (log)
        with open (cov_log, "a+") as lf:
            lf.write ("[" + str (round(time.time())) + "]" + log + "\n")
    
exit_fuzz ()