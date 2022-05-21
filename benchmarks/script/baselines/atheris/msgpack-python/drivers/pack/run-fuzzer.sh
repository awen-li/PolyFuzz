#!/bin/sh

python $BENCH/script/popen_log.py "python pack.py ./tests -rss_limit_mb=4096"

