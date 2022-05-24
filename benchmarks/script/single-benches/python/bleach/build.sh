

export ROOT=`cd ../../../../ && pwd`
export target=bleach

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	git clone https://github.com/mozilla/bleach
	
	pushd $target
	pip3 install .	
	popd
	
	PyDir=$target/bleach
    python -m parser $PyDir
    cp $PyDir/py_summary.xml $ROOT/script/single-benches/python/$target/
}


cd $ROOT
compile

