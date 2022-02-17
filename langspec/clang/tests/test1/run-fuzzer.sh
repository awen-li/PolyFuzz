
export AFL_SKIP_BIN_CHECK=1

if [ ! -d "fuzz" ]; then
    mkdir -p fuzz/in
    cp seeds/* fuzz/in/
fi

cd fuzz

afl-system-config

afl-fuzz $1 $2 -i in/ -o out -m none -d -- ../demo  @@

