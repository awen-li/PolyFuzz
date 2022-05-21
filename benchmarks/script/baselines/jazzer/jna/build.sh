

export ROOT=`cd ../../ && pwd`
export target=jna

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

	java -cp .:$JavaCovPCG/JavaCovPCG.jar JCovPCG.Main -t .
	cp sootOutput/* -rf .
	rm -rf sootOutput

	jar -cvfm $jar_name META-INF/MANIFEST.MF *
	chmod a+x $jar_name
	cp $jar_name ../
	mv EXTERNAL_LOC $ROOT/script/$target
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
	cp $ROOT/script/$target/Makefile $ROOT/$target/native/ -f
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


