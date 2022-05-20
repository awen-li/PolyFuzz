

export ROOT=`cd ../../../../ && pwd`
export target=tink

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/google/tink.git
	
	Protoc=`which protoc`
	if [ ! -n "$Protoc" ]; then
	    apt install -y protobuf-compiler
	    pip install google
	    pip install protobuf
	fi

	pushd $target/python
	
	cp $ROOT/script/$target/setup.py ./
	pip3 install .

	popd	
}


cd $ROOT && compile
