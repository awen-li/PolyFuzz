

export ROOT=`cd ../../../../ && pwd`
export target=pycryptodome

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/Legrandin/pycryptodome

	pushd $target

	python setup.py install
	
	popd
}


cd $ROOT
compile


