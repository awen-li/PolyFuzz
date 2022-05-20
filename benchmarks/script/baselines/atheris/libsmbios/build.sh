

export ROOT=`cd ../../../../ && pwd`
export target=libsmbios

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

function compile ()
{
	if [ ! -d "$ROOT/$target" ]; then
		git clone https://github.com/dell/libsmbios.git
	fi

	pushd $target
	
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

cd $ROOT
compile


