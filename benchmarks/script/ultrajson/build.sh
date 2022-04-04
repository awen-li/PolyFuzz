

export ROOT=`cd ../../ && pwd`
export target=ultrajson

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/ultrajson/ultrajson.git

	pushd $target
	
	export CC="afl-cc -lxFuzztrace"
	export CXX="afl-c++"

	python setup.py install
	
	popd
}

# 1. compile the C unit
cd $ROOT
compile

# 2. summarize the Python unit
PyDir=$target/tests
python -m parser $PyDir
cp $PyDir/py_summary.xml $ROOT/script/$target/
