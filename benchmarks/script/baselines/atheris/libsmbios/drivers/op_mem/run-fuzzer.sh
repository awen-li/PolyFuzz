#!/bin/sh

python op_mem.py ./tests > full.log 2>&1 &

python $BENCH/script/extract_log.py "op_mem.py"

rm -rf full.log