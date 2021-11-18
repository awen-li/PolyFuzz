
export PY_PATH=`pwd`


#1. buld parser
echo ""
echo ""
echo "@@@@@@@@@@@@@@@ build Python:parser @@@@@@@@@@@@@@@"
cd $PY_PATH/parser
pip3 install .
cd -

PyVersion=`python -c 'import platform; major, minor, patch = platform.python_version_tuple(); print(str(major)+"."+str(minor))'`
PYTHON_PATH=/usr/lib/python$PyVersion/
cp $PY_PATH/parser/parser.py $PYTHON_PATH
# anaconda environment
Anaconda=`which anaconda`
if [ -n "$Anaconda" ]; then
	PYTHON_PATH=/usr/lib/anaconda3/lib/python$PyVersion
	if [ -d "$PYTHON_PATH" ]; then
    	cp $PY_PATH/parser/parser.py $PYTHON_PATH
    	echo "Have installed parser to anaconda...."
    fi
fi


#2. build prob
echo ""
echo ""
echo "@@@@@@@@@@@@@@@ build Python:prob @@@@@@@@@@@@@@@"

