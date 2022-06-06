#urllib3
#!/bin/bash

cd /root/atheris_bench/urllib3/

nohup sh run.sh > full.log 2>&1 &

python3 extract_log.py 1800 $0
