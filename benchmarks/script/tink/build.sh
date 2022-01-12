

export ROOT=`cd ../../ && pwd`
export target=tink

function compile ()
{
	if [ ! -d "$ROOT/$target" ]; then
		git clone https://github.com/google/tink.git
	fi
	
	Protoc=`which protoc`
	if [ ! -n "$Protoc" ]; then
	    apt install -y protobuf-compiler
	    pip install google
	    pip install protobuf
	fi

	pushd $target/python
	
	export CC="afl-cc"
	export CXX="afl-c++"
	
    bazel clean --expunge
    cp $ROOT/script/$target/setup.py ./
	python setup.py install
	
	popd
}

# 1. compile the C unit
cd $ROOT
compile

# 2. summarize the Python unit
PyDir=$target/python/tink
python -m parser $PyDir
cp $PyDir/py_summary.xml $ROOT/script/$target/

cd $ROOT/script/$target/
python tink-test.py
