#!/bin/sh

export LD_PRELOAD="$(python -c "import atheris; print(atheris.path())")/asan_with_fuzzer.so"
export ASAN_OPTIONS=detect_leaks=0

python $BENCH/script/popen_log.py "python cmspack.py ./tests -rss_limit_mb=4096" &

