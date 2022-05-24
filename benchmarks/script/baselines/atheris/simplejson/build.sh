

export ROOT=`cd ../../../../ && pwd`
export target=simplejson

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/simplejson/simplejson

	pushd $target

	python setup.py install
	
	popd
}

cd $ROOT
compile

