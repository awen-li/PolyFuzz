

export ROOT=`cd ../../ && pwd`
export target=Pillow

function compile ()
{
	if [ ! -d "$ROOT/$target" ]; then
		git clone https://github.com/python-pillow/Pillow.git
	fi

	pushd $target
	
	export CC="afl-cc"
	export CXX="afl-c++"
	
	python setup.py install
	
	popd
}

# 1. compile the C unit
cd $ROOT
compile

# 2. summarize the Python unit
PyDir=$target/src/PIL
python -m parser $PyDir
cp $PyDir/py_summary.xml $ROOT/script/$target/
