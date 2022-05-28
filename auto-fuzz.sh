#!/bin/bash 

FUZZ_ROOT="/root/xFuzz"
BENCH_ROOT="$FUZZ_ROOT/benchmarks/script"
MULTI_BENCHS="aubio  bottleneck  jansi  jep  jna  libsmbios  msgpack-python  one-nio  Pillow  pycryptodome  pycurl  simplejson  tink  ultrajson  zstd-jni"
SINGLE_BENCHS="bind9  civetweb  cyclonedds  e2fsprogs  igraph apache-commons  javaparser  json-sanitizer  jsoup  zxing bleach  pygments  pyyaml  sqlalchemy  urllib3"
FUZZERS="polyfuzz atheris jazzer honggfuzz nsa-polyfuzz"


FUZZER_NAME=$1
IsOk=$(echo $FUZZERS | grep "$FUZZER_NAME")
if [ "$IsOk" == "" ] || [ "$FUZZER_NAME" == "" ]; then
	echo "@@@[Warning]please specify the fuzzer[$FUZZERS]:"
	exit 0
fi


BENCH_NAME=$2
IsOk=$(echo "$MULTI_BENCHS $SINGLE_BENCHS" | grep "$BENCH_NAME")
if [ "$IsOk" == "" ] || [ "$BENCH_NAME" == "" ]; then
	echo "@@@[Warning]None support benchmakrs:"
	echo "@@@[Multi-language  Benchmarks]: $MULTI_BENCHS"
	echo "@@@[Single-language Benchmarks]: $SINGLE_BENCHS"
	exit 0
fi

DRIVER_NAME=$3

export FUZZ_WORKING_DIR=""

###############################################################
# arg1: fuzzer name
# arg2: benchmark name
###############################################################
function getWorkingDir ()
{
	fuzzer=$1
	bench=$2
	
	if [ "$fuzzer" == "polyfuzz" ] || [ "$fuzzer" == "nsa-polyfuzz" ]; then
		IsOk=$(echo $MULTI_BENCHS | grep "$BENCH_NAME")
		if [ "$IsOk" != "" ]; then
			export FUZZ_WORKING_DIR="$BENCH_ROOT/multi-benches"
			return
		fi
		
		IsOk=$(echo $SINGLE_BENCHS | grep "$BENCH_NAME")
		if [ "$IsOk" != "" ]; then
			echo "result here is $IsOk"
			export FUZZ_WORKING_DIR="$BENCH_ROOT/single-benches/c $BENCH_ROOT/single-benches/python $BENCH_ROOT/single-benches/java"
			return
		fi	
	elif [ "$fuzzer" == "atheris" ]; then
		IsOk=$(echo $MULTI_BENCHS | grep "$BENCH_NAME")
		if [ "$IsOk" != "" ]; then
			export FUZZ_WORKING_DIR="$BENCH_ROOT/baselines/atheris"
			return
		fi		
	elif [ "$fuzzer" == "jazzer" ]; then
		IsOk=$(echo $MULTI_BENCHS | grep "$BENCH_NAME")
		if [ "$IsOk" != "" ]; then
			export FUZZ_WORKING_DIR="$BENCH_ROOT/baselines/jazzer"
			return
		fi
	elif [ "$fuzzer" == "honggfuzz" ]; then
		IsOk=$(echo $MULTI_BENCHS | grep "$BENCH_NAME")
		if [ "$IsOk" != "" ]; then
			export FUZZ_WORKING_DIR="$BENCH_ROOT/baselines/honggfuzz"
			return
		fi
	fi
	
	echo "@@@[Warning]$fuzzer do not support $BENCH_NAME"
	exit 0
}

###############################################################
# arg1: benchmark name
# arg2: benchmark dir
###############################################################
function buildBenchmark ()
{
	bname=$1
	benchmark=$2
	
	if [ ! -d "$bname" ]; then
		echo "[buildBenchmark]$bname not exist........."
		return 1
	fi

	cd $bname
	
	# 1. build the benchmark
	. build.sh
	cd $benchmark
	
	# 2. build the driver if necessary
	cd $bname/drivers
	if [ -f "build.sh" ]; then
		. build.sh
	fi

	return 0
}

###############################################################
# arg1: driver name
###############################################################
function runFuzzing ()
{
	driver=$1
	if [ ! -d "$driver" ]; then
		if [ -f "docker.cfg" ]; then
			driver=$(cat docker.in)
		else
			driver_list=`ls`
			for dr in $driver_list
			do
				if [ -d "$dr" ]; then
					driver=$dr
					break
				fi
			done
		fi
		
		if [ ! -d "$driver" ]; then
			echo "@@@[Warning]get driver fail..."
			exit 0
		fi 
	fi

	cd $driver
	
	is_baseline=$(echo $FUZZ_WORKING_DIR | grep "baseline")
	if [ "$is_baseline" == "" ]; then
		if [ "$fuzzer" == "nsa-polyfuzz" ]; then
			export AFL_TRACE_DU_SHUTDOWN=1
		fi
		
		./ple_entry.sh
	else
		./run-fuzzer.sh
	fi
}

# 1. build the fuzzer
cd $FUZZ_ROOT
. build.sh
cd -

# 2. get working directory
getWorkingDir $FUZZER_NAME $BENCH_NAME

# 3. build the benchmark
for benchmark in $FUZZ_WORKING_DIR
do
	cd $benchmark
	buildBenchmark $BENCH_NAME $benchmark
	if [ "$$?" != "0" ]; then
		continue
	fi
	
	cd $benchmark/$BENCH_NAME/drivers
	# 3. run the fuzzing
	runFuzzing $DRIVER_NAME
done