

export ROOT=`cd ../../ && pwd`
export target=zstd-jni

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
	java -cp .:$JavaCovPCG/JavaCovPCG.jar JCovPCG.Main -t com/github/luben/zstd
	cp sootOutput/* -rf com/github/luben/zstd/
	rm -rf sootOutput
	
	mv linux/amd64/branch_vars.bv $ROOT/$target/
	mv linux/amd64/cmp_statistic.info $ROOT/$target/
	mv EXTERNAL_LOC $ROOT/script/$target
	cat branch_vars.bv >> $ROOT/$target/branch_vars.bv
	rm branch_vars.bv
	rm INTERAL_LOC
	
	cp $ROOT/script/$target/MANIFEST.MF ./META-INF/ -f
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
	
	export CC="afl-cc"
	cp $ROOT/script/$target/build.sbt $ROOT/$target/ -f
	./sbt compile package
	
	jar_dir=$ROOT/$target/target/zstd-jni
	cd target
	instrument_java $jar_dir "zstd-jni-1.5.2-2.jar"
	cd ..
	
	popd
}

# 1. compile the C unit
cd $ROOT
compile


