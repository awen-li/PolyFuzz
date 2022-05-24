

export ROOT=`cd ../../ && pwd`
export target=jansi

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
	mv EXTERNAL_LOC $ROOT/script/$target
	
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
	cp $ROOT/script/$target/Makefile $ROOT/$target
    make CC="afl-cc -lxFuzztrace"
	
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


