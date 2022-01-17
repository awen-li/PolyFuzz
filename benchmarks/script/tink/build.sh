

export ROOT=`cd ../../ && pwd`
export target=tink
export drivers=$ROOT/script/$target/drivers

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

Action=$1
if [ "$Action" == "test" ]; then
    pushd $ROOT/$target/python
    export TINK_SRC_PATH=$ROOT/$target
    python setup.py test
    popd
    exit 0
fi


# 1. compile the C unit
cd $ROOT
compile

# 2. summarize the Python unit
PyDir=$target/python/tink
python -m parser $PyDir
if [ ! -d "$drivers" ]; then
	mkdir $drivers
fi
cp $PyDir/py_summary.xml $drivers/

cd $ROOT/script/$target/
python tink-test.py
