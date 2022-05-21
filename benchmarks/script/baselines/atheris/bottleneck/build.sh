

export ROOT=`cd ../../../../ && pwd`
export target=bottleneck


function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/pydata/bottleneck.git
	
	pushd $target
	
	pip3 install .
	
	popd
}


cd $ROOT
compile
