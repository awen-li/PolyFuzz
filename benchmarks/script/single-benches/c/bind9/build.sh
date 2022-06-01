

export ROOT=`pwd`
export target=bind9
export FUZZ_HOME="$ROOT/fuzz_root"

#dependences
function deps ()
{
	apt-get install -y python-ply
	apt-get install -y libuv1.dev
	apt-get install -y libnghttp2-dev
	apt-get install -y libjson-c-dev
	apt-get install -y libssl-dev
	apt-get install -y comerr-dev
}

	
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
	
	git clone https://gitlab.isc.org/isc-projects/bind9
	cd $target

	export CC="afl-cc -lxFuzztrace"
	export CXX="afl-c++ -lxFuzztrace"
	
	autoreconf -fi
	./configure --enable-developer --without-cmocka --without-zlib --disable-linux-caps --prefix="$FUZZ_HOME"
	

	make -j4
	make install

	cd -
	
	collect_branchs
	unset CC
	unset CXX
}


cd $ROOT
compile

cd $ROOT
