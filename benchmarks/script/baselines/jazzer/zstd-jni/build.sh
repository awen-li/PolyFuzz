

export ROOT=`cd ../../../../ && pwd`
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
	
	cp $ROOT/script/baselines/jazzer/$target/MANIFEST.MF ./META-INF/ -f
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
	
	LD_CLANG="$(python -c "import sysconfig; print(sysconfig.get_config_var('LDSHARED'))")"	
	LD_CLANG=`echo $LD_CLANG | sed 's/^gcc/clang/'`
		
	export LDSHARED=$LD_CLANG
	export CC="clang" CFLAGS="-fsanitize=fuzzer-no-link" CXX="clang++" CXXFLAGS="-fsanitize=fuzzer-no-link"
	
	export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
	update-java-alternatives --set java-1.8.0-openjdk-amd64

	cp $ROOT/script/baselines/jazzer/$target/build.sbt $ROOT/$target/ -f
	./sbt compile package
	
	jar_dir=$ROOT/$target/target/zstd-jni
	cd target
	jar_name=`find ./ -name "*.jar"`
	jar_name=`basename $jar_name`
	instrument_java $jar_dir $jar_name
	cd ..
	
	popd
}


cd $ROOT
compile




