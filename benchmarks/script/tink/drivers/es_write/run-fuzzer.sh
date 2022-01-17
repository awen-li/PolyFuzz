export AFL_SKIP_BIN_CHECK=1

if [ ! -d "fuzz" ]; then
   mkdir -p fuzz/in
   cp ./tests/* fuzz/in/
fi

cd fuzz
afl-system-config

#enable debug for child process
#export AFL_DEBUG_CHILD=1

#enable crash exit code
export AFL_CRASH_EXITCODE=100

cp ../../py_summary.xml ./
afl-fuzz $1 $2 -i in/ -o out -m none -d -- python ../es_write.py  @@

