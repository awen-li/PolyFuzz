#!/bin/sh

python $BENCH/script/popen_log.py "python decrypt-aes.py ./tests -rss_limit_mb=4096"
