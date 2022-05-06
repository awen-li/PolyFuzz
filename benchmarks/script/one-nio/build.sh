

export ROOT=`cd ../../ && pwd`
export target=one-nio

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

	echo "5000" > INTERAL_LOC
	get_onenio_deps
	java -cp .:$JavaCovPCG/JavaCovPCG.jar JCovPCG.Main -d deps -t one/nio
	cp sootOutput/* -rf one/nio/
	rm -rf sootOutput
	
	mv EXTERNAL_LOC $ROOT/script/$target
	cat branch_vars.bv >> $ROOT/$target/branch_vars.bv
	rm branch_vars.bv
	rm INTERAL_LOC
	rm deps
	
	cp $ROOT/script/$target/MANIFEST.MF ./META-INF/ -f
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
	
	cp $ROOT/script/$target/ant-build.xml $ROOT/$target/build.xml -f
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


