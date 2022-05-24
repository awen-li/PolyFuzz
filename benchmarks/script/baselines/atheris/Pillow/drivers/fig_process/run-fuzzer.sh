#!/bin/sh

python $BENCH/script/popen_log.py "python fig_process.py ./tests -rss_limit_mb=4096" &


