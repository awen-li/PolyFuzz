
#bench type
BENCH_TYPE=$1
if [ ! -n "$BENCH_TYPE" ]; then
	echo "please input the bench type for data collection[pls - polyfuzz single benches | plm - polyfuzz multi benches]...."
	exit 0
fi

#data dir
DATA_DIR=~/container_data
if [ ! -d "$DATA_DIR" ]; then
	mkdir $DATA_DIR
fi

ALL_CONTAINERS=`docker container ls --format 'table {{.Names}}'`
for container in $ALL_CONTAINERS
do
	if [ "$container" == "NAMES" ]; then
		continue;
	fi
	
	if [ "$BENCH_TYPE" == "pls" ]; then
		target_path="/root/xFuzz/benchmarks/script/single-benches/c /root/xFuzz/benchmarks/script/single-benches/python /root/xFuzz/benchmarks/script/single-benches/java"
	elif [ "$BENCH_TYPE" == "plm" ]; then
	    target_path="/root/xFuzz/benchmarks/script/multi-benches/"
	else
		echo "Unsupport bench type: $BENCH_TYPE"
		exit 0
	fi
	
	echo -e "@@@ Trying to collect data in $container "
	for path in $target_path
	do
		benches=`docker exec $container ls $path`
		
		for bench in $benches
		do
			echo -e "\t@@@ Trying to collect data in $container for $bench "
			file=`docker exec $container find $path/$bench -name perf_periodic.txt`
			if [ "$file" == "" ]; then
				continue
			fi
			
			log_path=$DATA_DIR/$container"_"$bench"_perf_periodic.txt"
			docker exec $container cat $file > $log_path 
		done
	done
done