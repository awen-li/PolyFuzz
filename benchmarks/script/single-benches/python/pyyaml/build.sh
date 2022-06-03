

export ROOT=`cd ../../../../ && pwd`
export target=pyyaml

apt-get install libyaml-dev

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	git clone https://github.com/yaml/pyyaml
	
	pushd $target
	python setup.py --without-libyaml install
	popd
	
	PyDir=$target/lib
    python -m parser $PyDir
    cp $PyDir/py_summary.xml $ROOT/script/single-benches/python/$target/
}


cd $ROOT
compile

