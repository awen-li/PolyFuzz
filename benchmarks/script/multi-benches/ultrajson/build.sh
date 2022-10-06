

export ROOT=`cd ../../../ && pwd`
export target=ultrajson
export ROOT_SCRIPT=$ROOT/script/multi-benches/$target

function collect_branchs ()
{
	ALL_BRANCHS=`find $ROOT/$target -name branch_vars.bv`
	
	if [ -f "$ROOT_SCRIPT/drivers/branch_vars.bv" ]; then
		rm $ROOT_SCRIPT/drivers/branch_vars.bv
	fi
	
	echo "@@@@@@@@@ ALL_BRANCHES -----> $ALL_BRANCHS"
	for branch in $ALL_BRANCHS
	do
		cat $branch >> $ROOT_SCRIPT/drivers/branch_vars.bv
		rm $branch
	done
}

function compile ()
{
	if [ ! -d "$ROOT/$target" ]; then
		git clone https://github.com/ultrajson/ultrajson.git
	fi

	pushd $target
	
	export CC="afl-cc -lxFuzztrace"
	export CXX="afl-c++"

	python setup.py install
	#pip install .
	
	popd
}

Pyversion=`PyVersion.sh`
if [ -d "$Pyversion/site-packages/ujson" ]; then
	rm -rf $Pyversion/site-packages/ujson*
fi

# 1. compile the C unit
cd $ROOT
compile

# 2. summarize the Python unit
cd $ROOT/$target/
PyDir=tests
python -m parser $PyDir  > python.log
cp $PyDir/py_summary.xml $ROOT_SCRIPT/

collect_branchs
cd $ROOT
