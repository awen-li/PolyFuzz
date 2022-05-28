
MULTI_BENCHS="aubio  bottleneck  jansi  jep  jna  libsmbios  msgpack-python  one-nio  Pillow  pycryptodome  pycurl  simplejson  tink  ultrajson  zstd-jni"
SINGLE_BENCHS="bind9  civetweb  cyclonedds  e2fsprogs  igraph apache-commons  javaparser  json-sanitizer  jsoup  zxing bleach  pygments  pyyaml  sqlalchemy  urllib3"
FUZZERS="polyfuzz atheris jazzer honggfuzz nsa-polyfuzz"
BENCHTYPE="single multi sole"

image=$1
input_fuzzer=$2
input_benchtype=$3

image_name=`echo $image | awk -F ":" '{print $1}'`
IsOk=$(docker image ls | grep "$image_name")
if [ "$IsOk" == "" ] || [ "$image_name" == "" ]; then
	echo "@Image $image_name not found...."
	exit 0
fi

IsOk=$(echo $FUZZERS | grep "$input_fuzzer")
if [ "$IsOk" == "" ] || [ "$input_fuzzer" == "" ]; then
	echo "@Support fuzzers: $FUZZERS"
	exit 0
fi

IsOk=$(echo $BENCHTYPE | grep "$input_benchtype")
if [ "$IsOk" == "" ] || [ "$input_benchtype" == "" ]; then
	echo "@Support benchtypes: $BENCHTYPE"
	exit 0
fi

function checkContainer ()
{
	container=$1
	if [[ -n $(docker ps -q -f "name=$container") ]]; then
		docker stop $container_name
		docker rm $container_name
	fi
}

# sole benchs
if [ "$input_benchtype" == "sole" ]; then
	benchmark=$4
	if [ "$benchmark" == "" ]; then
		echo "@In sole mode, please specify the name of benchmark. [$MULTI_BENCHS $SINGLE_BENCHS]"
		exit 0
	fi
	
	container_name="bench_"$input_fuzzer"_"$benchmark
	checkContainer $container_name
	
	docker run  -itd --name $container_name $image /bin/bash /root/xFuzz/auto-fuzz.sh $input_fuzzer $benchmark
else
    benchmakrs=$MULTI_BENCHS
	if [ "$input_benchtype" == "single" ]; then
		benchmakrs=$SINGLE_BENCHS
	fi
	
	for bench in $benchmakrs
	do
		container_name="bench_$input_fuzzer_$bench"
		checkContainer $container_name
		
		docker run  -itd --name $container_name $image /bin/bash /root/xFuzz.sh $input_fuzzer $benchmark
	done
fi

