

export ROOT=`cd ../../../ && pwd`
export target=libsmbios
export ROOT_SCRIPT=$ROOT/script/multi-benches/$target
export drivers=$ROOT_SCRIPT/drivers

function dependency ()
{
	pip install astunparse
	apt-get update
	apt-get install autopoint
	apt-get install libxml2-dev
	apt-get install gettext
}

PythonInstallPath ()
{
	PyBin=`which python`
	IsAnaconda=`echo $PyBin | grep anaconda`
	
	PyVersion=`python -c 'import platform; major, minor, patch = platform.python_version_tuple(); print(str(major)+"."+str(minor))'`
	if [ ! -n "$IsAnaconda" ]; then
	    echo "/usr/lib/python$PyVersion"
	else
	    echo "/root/anaconda3/lib/python$PyVersion"
	fi
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
	
	git clone https://github.com/dell/libsmbios.git

	pushd $target
	
	export CC="afl-cc -lxFuzztrace"
	export CXX="afl-c++ -lxFuzztrace"
	
	./autogen.sh
	make clean && make && make install
	
	# install python
	if [ -n "$CONDA_PYTHON_EXE" ]; then
		smb_dir=`find /usr/local/lib/python* -name "libsmbios_c"`
		cp $smb_dir -rf $(PythonInstallPath)/site-packages/
		rm -rf $smb_dir
	fi
	
	popd
}

Action=$1
if [ "$Action" == "dep" ]; then
	dependency
fi


# 1. compile the C unit
cd $ROOT
compile

# 2. summarize the Python unit
cd $ROOT/$target
PyDir=src/python
python -m parser $PyDir  > python.log
cp $PyDir/py_summary.xml $drivers/

collect_branchs