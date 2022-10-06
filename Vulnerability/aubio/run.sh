#!/bin/sh

python filter-test.py $1 > run.log 2>&1 &

n=1

while [ $n -le 10 ]
do
    info=`ps -aux | grep "filter-test.py" | grep "python"`
    mem_use=`echo $info | awk '{print $4}'`
    echo "[$n] `date`: memory percentage: $mem_use"
	
	n=$(( n+1 ))
	
	sleep 30
done

kill `echo $info | awk '{print $2}'`



