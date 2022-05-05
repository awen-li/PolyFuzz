

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
	
	cp $ROOT/$target/INTERAL_LOC $inst_dir/
	java -cp .:$JavaCovPCG/JavaCovPCG.jar JCovPCG.Main -t com/sun/jna
	cp sootOutput/* -rf com/sun/jna/
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
	
	git clone https://github.com/luben/zstd-jni.git

	pushd $target
	
	cp $ROOT/script/$target/build.sbt $ROOT/$target/ -f
	./sbt compile package
	
	jar_dir=$ROOT/$target/build/jna-instm
	#cd build
	#instrument_java $jar_dir "jna.jar"
	#cd ..
	
	popd
}

# 1. compile the C unit
cd $ROOT
compile


