export AFL_SKIP_BIN_CHECK=1

if [ ! -d "fuzz" ]; then
   mkdir -p fuzz/in
   cp -rf tests/* fuzz/in/
fi

cd fuzz
#afl-system-config

#enable debug for child process
#export AFL_DEBUG_CHILD=1


export AFL_PL_HAVOC_NUM=512
afl-fuzz $1 $2 -i in/ -o out -m none -d -- ../driver  @@

