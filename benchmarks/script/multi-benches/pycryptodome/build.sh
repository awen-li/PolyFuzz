

export ROOT=`cd ../../../ && pwd`
export target=pycryptodome
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
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/Legrandin/pycryptodome

	pushd $target
	
	export CC="afl-cc -lxFuzztrace"
	export CXX="afl-c++"
	
	cp $ROOT_SCRIPT/setup.py $ROOT/$target/
	python setup.py install
	
	popd
}

# 1. compile the C unit
cd $ROOT
compile

# 2. summarize the Python unit
cd $ROOT/$target/
PyDir=lib
python -m parser $PyDir  > python.log
cp $PyDir/py_summary.xml $ROOT_SCRIPT/

collect_branchs
