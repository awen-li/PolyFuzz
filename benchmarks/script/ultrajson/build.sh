

export ROOT=`cd ../../ && pwd`
export target=ultrajson

function compile ()
{
	if [ ! -d "$ROOT/$target" ]; then
		git clone https://github.com/ultrajson/ultrajson.git
	fi

	pushd $target
	
	export CC="afl-cc -lxFuzztrace"
	export CXX="afl-c++"
		
	rm -rf build
	#cp $ROOT/script/$target/setup.py ./ -f
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
