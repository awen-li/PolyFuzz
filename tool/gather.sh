
BENCH_ROOT="/root/xFuzz/benchmarks/script"
BENCH_PATHS="$BENCH_ROOT/single-benches/c $BENCH_ROOT/single-benches/python $BENCH_ROOT/single-benches/java $BENCH_ROOT/multi-benches/"

#data dir
DATA_DIR=~/container_data
if [ ! -d "$DATA_DIR" ]; then
	mkdir $DATA_DIR
fi

ALL_CONTAINERS=`docker container ls --format 'table {{.Names}}'`
for container in $ALL_CONTAINERS
do
	is_bench=$(echo $container | grep "bench_")
	if [ "$is_bench" == "" ]; then
		continue
	fi

	echo -e "@@@ Trying to collect data in $container "
	for path in $BENCH_PATHS
	do
		benches=`docker exec $container ls $path`
		if [ $? -ne 0 ]; then
			continue
		fi
		
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