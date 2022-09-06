

cd Python

export LD_PRELOAD="$(python -c "import atheris; print(atheris.path())")/asan_with_fuzzer.so"
export ASAN_OPTIONS=detect_leaks=0

python Demo.py ../tests

