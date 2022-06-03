

export ROOT=`cd ../../../ && pwd`
export target=jansi
export ROOT_SCRIPT=$ROOT/script/multi-benches/$target

function collect_branchs ()
{
	ALL_BRANCHS=`find $ROOT/$target -name branch_vars.bv`
	
	if [ -f "$ROOT_SCRIPT/drivers/branch_vars.bv" ]; then
		rm $ROOT_SCRIPT/drivers/branch_vars.bv
	fi
	
	echo "@@@@@@@@@ ALL_BRANCHES -----> $ALL_BRANCHS"
	for branch in $ALL_BRANCHS
	do
		cat $branch >> $ROOT_SCRIPT/drivers/branch_vars.bv
		rm $branch
	done
}


function instrument_java ()
{
	inst_dir=$1
	jar_name=$2
	
	pushd $inst_dir
	
	java -cp .:$JavaCovPCG/JavaCovPCG.jar JCovPCG.Main -t ./
	cp sootOutput/* -rf ./
	rm -rf sootOutput

	jar -cvfm $jar_name META-INF/MANIFEST.MF *
	chmod a+x $jar_name
	cp $jar_name ../
	mv EXTERNAL_LOC $ROOT_SCRIPT/
	
	popd
}

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/fusesource/jansi.git

	pushd $target
	
	# compile native
	cp $ROOT_SCRIPT/Makefile $ROOT/$target
	make clean-native native OS_NAME=Linux OS_ARCH=x86_64 CC="afl-cc -lxFuzztrace"
	
	# compile java
	mvn clean package
	
	# instrument java
	jar_dir=$ROOT/$target/target/classes
	instrument_java $jar_dir "jansi-2.4.1-SNAPSHOT.jar"
	
	popd
}

# 1. compile the C unit
cd $ROOT
compile

collect_branchs
cd $ROOT
