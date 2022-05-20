#!/bin/sh

python op_smbios.py ./tests > full.log 2>&1 &

python $BENCH/script/extract_log.py "op_smbios.py"

rm -rf full.log