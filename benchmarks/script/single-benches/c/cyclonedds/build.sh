

export ROOT=`pwd`
export target=cyclonedds
export FUZZ_HOME=$ROOT/fuzz_home
	
function collect_branchs ()
{
	ALL_BRANCHS=`find $ROOT/$target -name branch_vars.bv`
	
	if [ -f "$ROOT/drivers/branch_vars.bv" ]; then
		rm $ROOT/drivers/branch_vars.bv
	fi
	
	echo "@@@@@@@@@ ALL_BRANCHES -----> $ALL_BRANCHS"
	for branch in $ALL_BRANCHS
	do
		cat $branch >> $ROOT/drivers/branch_vars.bv
		rm $branch
	done
}


function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target*
	fi
	
	if [ ! -d "$FUZZ_HOME" ]; then
	    mkdir "$FUZZ_HOME"
	fi
	
	git clone https://github.com/eclipse-cyclonedds/cyclonedds.git
	cd $target

	export CC="afl-cc -fPIC -lxFuzztrace"
	export CXX="afl-c++ -fPIC -lxFuzztrace"
	
	mkdir build
	cd build
	cmake \
	    -DBUILD_IDLC=ON \
	    -DBUILD_SHARED_LIBS=OFF \
	    -DBUILD_EXAMPLES=NO \
	    -DENABLE_SECURITY=NO \
	    -DENABLE_SSL=NO \
	    -DCMAKE_INSTALL_PREFIX=$FUZZ_HOME ..
	cmake --build .
	cmake --build . --target install
	cd -
	
	collect_branchs
	unset CC
	unset CXX
}


cd $ROOT
compile


cd $ROOT