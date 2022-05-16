
export AFL_SKIP_BIN_CHECK=1

if [ ! -d "fuzz" ]; then
   mkdir -p fuzz/in
   cp ./tests/* fuzz/in/
fi

export TARGET_JAR=Decompress.jar

cp $TARGET_JAR fuzz/

cd fuzz
#afl-system-config

#enable debug for child process
export AFL_DEBUG_CHILD=1

JAR_PATH=`ls $BENCH/zstd-jni/target/zstd-jni*.jar`
export ZSTD_PATH=$JAR_PATH

#enable crash exit code
export AFL_CRASH_EXITCODE=100


cp ../../../EXTERNAL_LOC ./
if [ "$?" != "0" ]; then
	echo "copy EXTERNAL_LOC fail, please check the configuration!!!!"
	exit 0
fi

export AFL_PL_HAVOC_NUM=512
afl-fuzz $1 $2 -i in/ -o out -m none -d -- javawrapper java -cp $TARGET_JAR:$JavaCovPCG/JavaCovPCG.jar:$ZSTD_PATH DcmpZstd.DeCompress  @@

