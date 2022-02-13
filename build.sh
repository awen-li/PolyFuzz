
BASE_DIR=`pwd`

# 1. build AFL++
cd $BASE_DIR/AFLplusplus
if [ ! -f "afl-cc" ]; then
    make source-only
else
    make
fi

# 2. build common component
cd $BASE_DIR/common/
make clean && make

# 3. build language-specific component
# 3.1 clang

# 3.2 java
cd $BASE_DIR/langspec/java
./build.sh

# 3.3 python
cd $BASE_DIR/langspec/python
./pybuild.sh

# 4 tools
cd $BASE_DIR/tool/BBstat
make clean && make
