
export JavaCovPCG=/usr/lib/JavaCovPCG
export Jep=/root/anaconda3/lib/python3.9/site-packages/jep

export AFL_SKIP_BIN_CHECK=1

if [ ! -d "fuzz" ]; then
   mkdir -p fuzz/in
   cp ./tests/* fuzz/in/
fi

cp JepDr1.jar fuzz/

cd fuzz
afl-system-config

#enable debug for child process
#export AFL_DEBUG_CHILD=1

#enable crash exit code
export AFL_CRASH_EXITCODE=100

export AFL_PL_HAVOC_NUM=512
afl-fuzz $1 $2 -i in/ -o out -t 10000 -m none -d -- java -cp $JavaCovPCG/JavaCovPCG.jar:$Jep/jep-4.0.3.jar:JepDr1.jar JepDr.JepDrOne  @@

