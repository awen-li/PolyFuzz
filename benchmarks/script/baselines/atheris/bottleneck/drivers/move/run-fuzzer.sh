#!/bin/sh

python move.py ./tests -rss_limit_mb=4096 > full.log 2>&1 &


python $BENCH/script/extract_log.py "move.py"

