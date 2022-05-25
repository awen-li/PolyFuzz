
export AFL_SKIP_BIN_CHECK=1

if [ ! -d "fuzz" ]; then
    mkdir -p fuzz/in
    cp seeds/* fuzz/in/
    cp test2.jar fuzz/
    cp /usr/lib/JavaCovPCG/* -rf fuzz/
fi

cd fuzz

afl-system-config

#pilot fuzzing: max path length
export AFL_BB_NUM=1024

#enable debug for child process
export AFL_DEBUG_CHILD=1

#enable crash exit code 
export AFL_CRASH_EXITCODE=100

afl-fuzz $1 $2 -i in/ -o out -m none -d -- java -jar test2.jar @@

