

export ROOT=`cd ../../ && pwd`
export target=Nuitka

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/Nuitka/Nuitka

	pushd $target
	
	export CC="afl-cc -lxFuzztrace"
	export CXX="afl-c++"

	python setup.py install
	
	popd
}

# 1. compile the C unit
cd $ROOT
compile

exit 0

# 2. summarize the Python unit
PyDir=$target/lib
python -m parser $PyDir
cp $PyDir/py_summary.xml $ROOT/script/$target/
