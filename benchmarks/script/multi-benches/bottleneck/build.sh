

export ROOT=`cd ../../../ && pwd`
export target=bottleneck
export ROOT_SCRIPT=$ROOT/script/multi-benches/$target

function dep ()
{
	pip uninstall numpy
	pip install numpy
}

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
	
	git clone https://github.com/pydata/bottleneck.git
	
	pushd $target
	
	export CC="afl-cc -lxFuzztrace"
	export CXX="afl-c++"
	
	cp $ROOT/script/$target/setup.py $ROOT/$target/
	#python setup.py install
	pip3 install .
	
	popd
}

# 1. compile the C unit
cd $ROOT
compile

# 2. summarize the Python unit
PyDir=$target/bottleneck
python -m parser $PyDir
cp $PyDir/py_summary.xml $ROOT/script/$target/

collect_branchs