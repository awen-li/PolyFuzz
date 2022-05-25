

export ROOT=`cd ../../ && pwd`
export target=jep

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/ninia/jep.git
	
	pushd $target
	
	rm -rf build
	
	export CC="afl-cc"
	cp -f $ROOT/script/$target/java.py     $ROOT/$target/commands/
	cp -f $ROOT/script/$target/setup.py    $ROOT/$target/
	cp -f $ROOT/script/$target/INTERAL_LOC $ROOT/$target/
	python setup.py install
	
	cp $ROOT/$target/EXTERNAL_LOC $ROOT/script/$target/
	
	popd
}

# 1. compile the C unit
cd $ROOT
compile

