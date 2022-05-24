

export ROOT=`cd ../../../../ && pwd`
export target=sqlalchemy

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	git clone https://github.com/sqlalchemy/sqlalchemy
	
	pushd $target
	python setup.py install
	popd
	
	PyDir=$target/lib/sqlalchemy
    python -m parser $PyDir
    cp $PyDir/py_summary.xml $ROOT/script/single-benches/python/$target/
}


cd $ROOT
compile

