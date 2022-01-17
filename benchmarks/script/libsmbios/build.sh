

export ROOT=`cd ../../ && pwd`
export target=libsmbios
export drivers=$ROOT/script/$target/drivers

function compile ()
{
	if [ ! -d "$ROOT/$target" ]; then
		git clone https://github.com/dell/libsmbios.git
	fi

	pushd $target
	
	export CC="afl-cc -lxFuzztrace"
	export CXX="afl-c++ -lxFuzztrace"
	
	./autogen.sh
	make clean && make && make install
	
	# install python
	if [ -n "$CONDA_PYTHON_EXE" ]; then
		cp /usr/local/lib/python3.9/site-packages/libsmbios_c -rf /root/anaconda3/lib/python3.9/site-packages/
		rm -rf /usr/local/lib/python3.9/site-packages/libsmbios_c
	fi
	
	popd
}

# 1. compile the C unit
cd $ROOT
compile

# 2. summarize the Python unit
PyDir=$target/src/python
python -m parser $PyDir
cp $PyDir/py_summary.xml $drivers/
