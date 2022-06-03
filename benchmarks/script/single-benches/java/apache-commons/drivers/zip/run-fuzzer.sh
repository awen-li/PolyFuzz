
export AFL_SKIP_BIN_CHECK=1

if [ ! -d "fuzz" ]; then
   mkdir -p fuzz/in
   cp ./tests/* fuzz/in/
fi

export target=zip.jar
cp $target fuzz/

cd fuzz
#afl-system-config

#enable debug for child process
export AFL_DEBUG_CHILD=1
export TARGET_APP=$BENCH/script/single-benches/java/apache-commons/commons-compress.jar

#enable crash exit code
export AFL_CRASH_EXITCODE=100


cp ../../../EXTERNAL_LOC ./
if [ "$?" != "0" ]; then
	echo "copy EXTERNAL_LOC fail, please check the configuration!!!!"
	exit 0
fi

export AFL_PL_HAVOC_NUM=512
afl-fuzz $1 $2 -i in/ -o out -t 5000 -m none -d -- javawrapper java -cp $target:$JavaCovPCG/JavaCovPCG.jar:$TARGET_APP zip.getEntries  @@

