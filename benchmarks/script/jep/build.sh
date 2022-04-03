

export ROOT=`cd ../../ && pwd`
export target=jep

function compile ()
{
	if [ ! -d "$ROOT/$target" ]; then
		git clone https://github.com/ninia/jep.git
	fi

	pushd $target
	
	rm -rf build
	
	export CC="afl-cc -lxFuzztrace"
	export CXX="afl-c++"
	cp -f $ROOT/script/$target/java.py $ROOT/$target/commands/
	python setup.py install
	
	popd
}

# 1. compile the C unit
cd $ROOT
compile

# 2. summarize the Python unit
PyDir=$target/src/main/python
python -m parser $PyDir
cp $PyDir/py_summary.xml $ROOT/script/$target/
