#!/bin/sh

python image_open.py ./tests -rss_limit_mb=4096 > full.log 2>&1 &


python $BENCH/script/extract_log.py "image_open.py"
