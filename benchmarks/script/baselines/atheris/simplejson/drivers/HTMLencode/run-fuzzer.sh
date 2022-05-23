#!/bin/sh

python $BENCH/script/popen_log.py "python encode.py ./tests -rss_limit_mb=4096" &

