

export ROOT=`cd ../../../../ && pwd`
export target=msgpack-python

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/msgpack/msgpack-python

	pushd $target

	python setup.py install
	
	popd
}


cd $ROOT
compile
