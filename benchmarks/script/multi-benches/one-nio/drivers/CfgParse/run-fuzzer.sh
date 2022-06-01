
export AFL_SKIP_BIN_CHECK=1

if [ ! -d "fuzz" ]; then
   mkdir -p fuzz/in
   cp ./tests/* fuzz/in/
fi

export TARGET_JAR=CfgParse.jar

cp $TARGET_JAR fuzz/

cd fuzz
#afl-system-config

#enable debug for child process
export AFL_DEBUG_CHILD=1
export ONENIO_PATH=$BENCH/one-nio/build/one-nio.jar:$BENCH/one-nio/lib/asm-9.2.jar:$BENCH/one-nio/lib/commons-logging-1.2.jar::$BENCH/one-nio/lib/log4j-1.2.17.jar

#enable crash exit code
export AFL_CRASH_EXITCODE=100


cp ../../../EXTERNAL_LOC ./
if [ "$?" != "0" ]; then
	echo "copy EXTERNAL_LOC fail, please check the configuration!!!!"
	exit 0
fi

export AFL_PL_HAVOC_NUM=512
afl-fuzz $1 $2 -i in/ -o out -m none -d -- javawrapper java -cp $TARGET_JAR:$JavaCovPCG/JavaCovPCG.jar:$ONENIO_PATH CfgParseDrv.CfgParseDrv  @@

