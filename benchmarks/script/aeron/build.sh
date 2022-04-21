

export ROOT=`cd ../../ && pwd`
export target=aeron

function instrument_java ()
{
	dir=$1
	jar_name=$2
	
	inst_dir=$1/instrument
	mkdir $inst_dir
	
	pushd $dir/instrument
	
	jar xvf ../$jar_name 
	
	java -cp .:$JavaCovPCG/JavaCovPCG.jar JCovPCG.Main -t ./
	cp sootOutput/* -rf ./
	rm -rf sootOutput
	
	jar -cvfm $jar_name META-INF/MANIFEST.MF *
	chmod a+x $jar_name
	cp $jar_name ../
	cp $dir/instrument/EXTERNAL_LOC $ROOT/script/$target
	
	popd
}

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/real-logic/aeron.git

	pushd $target
	
	export CC="afl-cc -lxFuzztrace"
	export CXX="afl-c++"
	export AFL_TRACE_DU_SHUTDOWN=1
	
	# compile java
	./gradlew
	
	# instrument java
	jar_dir=$ROOT/$target/aeron-all/build/libs
	Jar=`ls $jar_dir/aeron*.jar`
	instrument_java $jar_dir `cd $jar_dir && ls `
	
	# compile C
	./cppbuild/cppbuild
	
	unset AFL_TRACE_DU_SHUTDOWN
	popd
}

# 1. compile the C unit
cd $ROOT
compile


