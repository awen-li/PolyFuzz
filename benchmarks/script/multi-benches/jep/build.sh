

export ROOT=`cd ../../../ && pwd`
export target=jep
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
	
	git clone https://github.com/ninia/jep.git
	
	pushd $target
	
	rm -rf build
	
	export CC="afl-cc"
	cp -f $ROOT_SCRIPT/java.py     $ROOT/$target/commands/
	cp -f $ROOT_SCRIPT/setup.py    $ROOT/$target/
	cp -f $ROOT_SCRIPT/INTERAL_LOC $ROOT/$target/
	python setup.py install
	
	cp $ROOT/$target/EXTERNAL_LOC $ROOT_SCRIPT/
	
	popd
}

# 1. compile the C unit
cd $ROOT
compile

collect_branchs
cd $ROOT