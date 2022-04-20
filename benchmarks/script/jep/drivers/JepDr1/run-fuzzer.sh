
export AFL_SKIP_BIN_CHECK=1

if [ ! -d "fuzz" ]; then
   mkdir -p fuzz/in
   cp ./tests/* fuzz/in/
fi

cp JepDr1.jar fuzz/
cp subprocess fuzz/ -rf

cd fuzz
#afl-system-config

#enable debug for child process
export AFL_DEBUG_CHILD=1

#enable crash exit code
export AFL_CRASH_EXITCODE=100


cp ../../../EXTERNAL_LOC ./
if [ "$?" != "0" ]; then
	echo "copy EXTERNAL_LOC fail, please check the configuration!!!!"
	exit 0
fi

export AFL_PL_HAVOC_NUM=512
afl-fuzz $1 $2 -i in/ -o out -m none -d -- javawrapper java -cp $JavaCovPCG/JavaCovPCG.jar:$JepPath/jep-4.0.3.jar:JepDr1.jar JepDr.JepDrOne  @@

