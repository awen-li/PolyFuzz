

export ROOT=`cd ../../../ && pwd`
export target=one-nio
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

function get_onenio_deps ()
{
	depslist=`ls $ROOT/$target/lib/*.jar`
	for dep in ${depslist[@]}
	do
		echo $dep >> deps
	done
}

function instrument_java ()
{
	inst_dir=$1
	jar_name=$2
	
	if [ ! -d "$inst_dir" ]; then
		mkdir $inst_dir
	fi
	
	cd $inst_dir
	jar -xvf ../$jar_name
	
	JAVA_8=`echo $JAVA_HOME | grep java-8`
	if [ ! -n "$JAVA_8" ]; then
		export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
		update-java-alternatives --set $JAVA_HOME
	fi

	echo "5000" > INTERAL_LOC
	get_onenio_deps
	java -cp .:$JavaCovPCG/JavaCovPCG.jar JCovPCG.Main -d deps -t ./
	cp sootOutput/* -rf ./
	rm -rf sootOutput
	
	mv EXTERNAL_LOC $ROOT_SCRIPT/
	cat branch_vars.bv >> $ROOT/$target/branch_vars.bv
	rm branch_vars.bv
	rm INTERAL_LOC
	rm deps
	
	jar -cvfm $jar_name META-INF/MANIFEST.MF *
	chmod a+x $jar_name
	cp $jar_name ../
}

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/odnoklassniki/one-nio.git

	pushd $target
	
	cp $ROOT_SCRIPT/ant-build.xml $ROOT/$target/build.xml -f
	ant
	
	jar_dir=$ROOT/$target/build/one-nio-instm
	cd build
	instrument_java $jar_dir "one-nio.jar"
	cd ..
	
	popd
}

# 1. compile the C unit
cd $ROOT
compile


collect_branchs
