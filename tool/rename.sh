dir=$1
prefix=$2
ALL=`ls $dir/$prefix*`
No=1
for F in $ALL
do
	mv $F $dir/"p-test-$No"
	let No++
done