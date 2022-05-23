

export ROOT=`cd ../../../../ && pwd`
export target=one-nio


function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/odnoklassniki/one-nio.git

	pushd $target
	
	ant
	
	popd
}

cd $ROOT
compile


