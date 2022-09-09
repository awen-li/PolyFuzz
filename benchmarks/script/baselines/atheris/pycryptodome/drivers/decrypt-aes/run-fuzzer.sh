#!/bin/sh

export LD_PRELOAD="$(python -c "import atheris; print(atheris.path())")/asan_with_fuzzer.so"
export ASAN_OPTIONS=detect_leaks=0
export PYCRYPTODOME_DISABLE_DEEPBIND=1

python $BENCH/script/popen_log.py "python decrypt-aes.py ./tests -rss_limit_mb=4096" &

