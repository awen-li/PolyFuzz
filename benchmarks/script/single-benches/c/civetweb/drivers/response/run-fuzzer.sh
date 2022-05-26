export AFL_SKIP_BIN_CHECK=1

if [ ! -d "fuzz" ]; then
   mkdir -p fuzz/in
   cp -rf tests/* fuzz/in/
fi

cd fuzz
#afl-system-config

export AFL_PL_HAVOC_NUM=512
afl-fuzz $1 $2 -i in/ -o out -t 5000 -m none -d -- ../driver  @@

