

export ROOT=`cd ../../../../ && pwd`
export target=aubio

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/aubio/aubio.git
	
	pushd $target
	
	pip install .

	popd
}

# 1. compile the C unit
cd $ROOT
compile

