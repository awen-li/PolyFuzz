

export ROOT=`cd ../../ && pwd`
export target=bottleneck

function dep ()
{
	conda install nomkl
}

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/pydata/bottleneck.git
	
	pushd $target
	
	export CC="afl-cc -lxFuzztrace"
	export CXX="afl-c++"
	
	cp $ROOT/script/$target/setup.py $ROOT/$target/
	#python setup.py install
	pip3 install .
	
	popd
}

# 1. compile the C unit
cd $ROOT
compile

# 2. summarize the Python unit
PyDir=$target/bottleneck
python -m parser $PyDir
cp $PyDir/py_summary.xml $ROOT/script/$target/
