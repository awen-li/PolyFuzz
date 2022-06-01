

export ROOT=`cd ../../../ && pwd`
export target=aubio
export ROOT_SCRIPT=$ROOT/script/multi-benches/$target

function deps ()
{
    apt-get install ffmpeg 
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
	
	git clone https://github.com/aubio/aubio.git
	
	pushd $target
	
	export CC="afl-cc -lxFuzztrace"
	export CXX="afl-c++"
	
	export AFL_TRACE_DU_SHUTDOWN=1
	make
	cp build/src/libaubio* /usr/lib/
	
	#python setup.py install
	pip install -v .
	unset AFL_TRACE_DU_SHUTDOWN
	popd
}

# 1. compile the C unit
cd $ROOT
compile

# 2. summarize the Python unit
cd $ROOT/$target
PyDir=python
python -m parser $PyDir  > python.log
cp $PyDir/py_summary.xml $ROOT_SCRIPT/

collect_branchs
cd $ROOT
