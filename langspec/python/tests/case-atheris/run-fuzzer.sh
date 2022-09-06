

cd Python

export LD_PRELOAD="$(python -c "import atheris; print(atheris.path())")/asan_with_fuzzer.so" 
python Demo.py ../tests

