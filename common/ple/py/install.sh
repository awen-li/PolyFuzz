
PythonInstallPath ()
{
	PyBin=`which python`
	IsAnaconda=`echo $PyBin | grep anaconda`
	
	PyVersion=`python -c 'import platform; major, minor, patch = platform.python_version_tuple(); print(str(major)+"."+str(minor))'`
	if [ ! -n "$IsAnaconda" ]; then
	    echo "/usr/lib/python$PyVersion"
	else
		IsRoot=`echo $PyBin | grep root`
	    if [ -n "$IsRoot" ]; then
	        echo "/root/anaconda3/lib/python$PyVersion"
	    else
	        echo "/usr/lib/anaconda3/lib/python$PyVersion"
	    fi
	fi
}

pip install sklearn

PythonPath=$(PythonInstallPath)
cp ./*.py $PythonPath/
