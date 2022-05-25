

export ROOT=`cd ../../../../ && pwd`
export target=Pillow

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/python-pillow/Pillow.git
	
	pushd $target
	
	python setup.py install

	popd
}


cd $ROOT
compile
