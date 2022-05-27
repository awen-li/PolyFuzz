

export ROOT=`cd ../../../ && pwd`
export target=zstd-jni
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
		cd --
	fi
	
	pushd $inst_dir

	echo "5000" > INTERAL_LOC
	java -cp .:$JavaCovPCG/JavaCovPCG.jar JCovPCG.Main -t ./
	cp sootOutput/* -rf ./
	rm -rf sootOutput
	
	mv linux/amd64/branch_vars.bv $ROOT/$target/
	mv linux/amd64/cmp_statistic.info $ROOT/$target/
	mv EXTERNAL_LOC $ROOT_SCRIPT/
	cat branch_vars.bv >> $ROOT/$target/branch_vars.bv
	rm branch_vars.bv
	rm INTERAL_LOC
	
	cp $ROOT_SCRIPT/MANIFEST.MF ./META-INF/ -f
	jar -cvfm $jar_name META-INF/MANIFEST.MF *
	chmod a+x $jar_name
	cp $jar_name ../
	
	popd
}

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/luben/zstd-jni.git

	pushd $target
	
	export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
	update-java-alternatives --set java-1.8.0-openjdk-amd64
	
	export CC="afl-cc"
	cp $ROOT_SCRIPT/build.sbt $ROOT/$target/ -f
	./sbt compile package
	
	jar_dir=$ROOT/$target/target/zstd-jni
	cd target
	jar_name=`find ./ -name "*.jar"`
	jar_name=`basename $jar_name`
	instrument_java $jar_dir $jar_name
	cd ..
	
	popd
}

# 1. compile the C unit
cd $ROOT
compile


collect_branchs