#!/bin/sh

python decrypt.py ./tests > full.log 2>&1 &

python $BENCH/script/extract_log.py "decrypt.py"

rm -rf full.log