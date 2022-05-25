

export ROOT=`cd ../../../../ && pwd`
export target=urllib3

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	git clone https://github.com/urllib3/urllib3
	
	pushd $target
	pip3 install .	
	popd
	
	PyDir=$target/src/urllib3
    python -m parser $PyDir
    cp $PyDir/py_summary.xml $ROOT/script/single-benches/python/$target/
}


cd $ROOT
compile

