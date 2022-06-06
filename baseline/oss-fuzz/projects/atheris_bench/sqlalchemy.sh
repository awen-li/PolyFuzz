#sqlalchemy
#!/bin/bash

cd /root/atheris_bench/sqlalchemy/

nohup sh run.sh > full.log 2>&1 &

python3 extract_log.py 1800 $0
