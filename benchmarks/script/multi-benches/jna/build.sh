

export ROOT=`cd ../../../ && pwd`
export target=jna
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
	
	if [ ! -d "$inst_dir" ]; then
		mkdir $inst_dir
		cd $inst_dir
		jar -xvf ../$jar_name
		cd -
	fi
	
	cd $inst_dir
	
	cp $ROOT/$target/INTERAL_LOC $inst_dir/

	java -cp .:$JavaCovPCG/JavaCovPCG.jar JCovPCG.Main -t ./com
	cp sootOutput/* -rf ./com
	rm -rf sootOutput

	jar -cvfm $jar_name META-INF/MANIFEST.MF *
	chmod a+x $jar_name
	cp $jar_name ../
	mv EXTERNAL_LOC $ROOT_SCRIPT/
}

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/java-native-access/jna.git
	
	
	JAVA_8=`echo $JAVA_HOME | grep java-8`
	if [ ! -n "$JAVA_8" ]; then
		export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
		update-java-alternatives --set java-1.8.0-openjdk-amd64
	fi

	cd $target
	
	# compile native
	cp $ROOT_SCRIPT/Makefile $ROOT/$target/native/ -f
	cd native
	ant
	cd ..
    
	# compile java
	ant
	
	# instrument java
	jar_dir=$ROOT/$target/build/$target-instm
	cd build
	instrument_java $jar_dir "jna.jar" 
}

# 1. compile the C unit
cd $ROOT
compile


collect_branchs
cd $ROOT
