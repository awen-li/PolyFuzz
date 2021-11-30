
BASE_DIR=`pwd`

# 1. build AFL++
cd $BASE_DIR/AFLplusplus
if [ -f "afl-cc" ]; then
    make source-only
else
    make
fi

# 2. build common component
cd $BASE_DIR/common/ctrace
make clean && make

# 3. build language-specific component
# 3.1 clang

# 3.2 java

# 3.3 python
cd $BASE_DIR/langspec/python
./pybuild.sh

