
export AFL_SKIP_BIN_CHECK=1

cd Python
if [ ! -d "fuzz" ]; then
    mkdir -p fuzz/in
    cp ../tests/* fuzz/in/
fi

cd fuzz

afl-system-config

#enable debug for child process
export AFL_DEBUG_CHILD=1

cp ../branch_variables.xml ./
afl-fuzz -i in/ -o out -m none -d -- python ../Demo.py  @@