import fileinput
import time
import os

target_file = 'full.log'
init_flag = True  
time_kick = 1800

record_count = 0

while True:
    if not os.path.exists(target_file):
        time.sleep(time_kick)
        continue

    try:
        if init_flag:
            f_w = open('pyyaml.log', 'w')
            with open(target_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                last_line = lines[-1]
                f_w.write(last_line + "\n")
                record_count += 1

            init_flag = False
        else:
            f_w = open('pyyaml.log', 'a')
            with open(target_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                last_line = lines[-1]
                f_w.write(last_line + "\n")
                record_count += 1

        f_w.close()
    except:
        pass
    time.sleep(time_kick)
