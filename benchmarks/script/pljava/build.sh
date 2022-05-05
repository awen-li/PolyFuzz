

export ROOT=`cd ../../ && pwd`
export target=pljava

function deps ()
{
	apt-get install openjdk-11-jdk
	apt-get install -y postgresql-server-dev-all
	apt-get install -y libkrb5-dev
	apt-get install libssl-dev
}

function instm_sub_jar ()
{
	sub_jar=$2
	sub_dir=$1
	mkdir $sub_dir
	
	cd $sub_dir
	pwd
	jar -xvf ../$sub_jar
	
	if [ -f "$ROOT/script/$target/EXTERNAL_LOC" ]; then
	    cat $ROOT/script/$target/EXTERNAL_LOC > INTERAL_LOC
	else
		echo "5000" > INTERAL_LOC
	fi

	echo "../pljava-api-2-SNAPSHOT.jar" > deps
	java -cp .:$JavaCovPCG/JavaCovPCG.jar JCovPCG.Main -d deps -t org/postgresql/pljava 
	cp sootOutput/* -rf org/postgresql/pljava
	rm -rf sootOutput
	mv EXTERNAL_LOC $ROOT/script/$target/
	
	cat branch_vars.bv >> $ROOT/$target/branch_vars.bv
	rm branch_vars.bv
	rm deps
	
	jar -cvfm $sub_jar META-INF/MANIFEST.MF *
	chmod a+x $sub_jar
	mv $sub_jar ../
	
	cd -
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
	
	# pljava/sharedir/pljava
	instm_sub_jar $inst_dir/pljava/sharedir/pljava/pljava-instm     "pljava-2-SNAPSHOT.jar"
	instm_sub_jar $inst_dir/pljava/sharedir/pljava/pljava-api-instm "pljava-api-2-SNAPSHOT.jar"
	
	rm -rf $inst_dir/pljava/sharedir/pljava/pljava-instm
	rm -rf $inst_dir/pljava/sharedir/pljava/pljava-api-instm
	
	jar -cvfm $jar_name META-INF/MANIFEST.MF *
	chmod a+x $jar_name
	mv $jar_name ../

}

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/tada/pljava.git

	pushd $target
	
	export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64 
	export CC="afl-cc"
	cp $ROOT/script/$target/pom.xml $ROOT/$target/pljava-so/ -f
	mvn clean install #-X 
	
	jar_dir=$ROOT/$target/pljava-packaging/target/pljava-instm
	cd pljava-packaging/target
	instrument_java $jar_dir "pljava-pg10.jar"
	cd ..
	
	popd
}

# 1. compile the C unit
cd $ROOT
compile


