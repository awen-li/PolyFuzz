

export ROOT=`cd ../../../ && pwd`
export target=Pillow
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
		git clone https://github.com/python-pillow/Pillow.git
	fi
	
	pushd $target
	
	export CC="afl-cc -lxFuzztrace"
	export CXX="afl-c++ -lxFuzztrace"
		
	cp $ROOT_SCRIPT/setup.py ./ -f
	python setup.py install

	popd
}

# 1. compile the C unit
cd $ROOT
compile

# 2. summarize the Python unit
cd $ROOT/$target
PyDir=src/PIL
python -m parser $PyDir  > python.log
cp $PyDir/py_summary.xml $ROOT_SCRIPT/

collect_branchs
cd $ROOT
