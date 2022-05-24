

export ROOT=`cd ../../../../ && pwd`
export target=jep

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/ninia/jep.git
	
	pushd $target
	
	python setup.py install
	
	popd
}


cd $ROOT
compile

