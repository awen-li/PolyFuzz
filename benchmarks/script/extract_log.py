import fileinput
import time
import os
import sys

target_file = 'full.log'
init_flag = True  
time_kick = 10

record_count = 0

def is_exist (target):
    cmd = "ps -elf | grep " + sys.argv[1] + " | grep -v grep | grep -v extract_log.py"
    exist = os.popen(cmd).read()
    print (exist)
    if len (exist) < 4:
        return False
    else:
        return True

target = sys.argv[1]

while True:
    if not os.path.exists(target_file):
        time.sleep(time_kick)
        exists = is_exist (target)
        if exists == False:
            print ("Not detect the target %s, exit now....." %target)
            break
        continue

    try:
        if init_flag:
            f_w = open('bleach.log', 'w')
            with open(target_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                last_line = lines[-1]
                f_w.write(last_line + "\n")
                record_count += 1

            init_flag = False
        else:
            f_w = open('bleach.log', 'a')
            with open(target_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                last_line = lines[-1]
                f_w.write(last_line + "\n")
                record_count += 1

        f_w.close()
    except:
        pass
    time.sleep(time_kick)
    
    os.remove (target_file)
    exists = is_exist (target)
    if exists == False:
        print ("Not detect the target %s, exit now....." %target)
        break
    
