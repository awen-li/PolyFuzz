

export ROOT=`cd ../../../../ && pwd`
export target=ultrajson

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/ultrajson/ultrajson.git

	pushd $target

	pip install .
	
	popd
}

cd $ROOT
compile

