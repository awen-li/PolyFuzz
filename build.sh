
BASE_DIR=`pwd`

# 1. build common/ple
cd $BASE_DIR/common/ple
make clean && make

# 2. build AFL++
cd $BASE_DIR/AFLplusplus
if [ ! -f "afl-cc" ]; then
    make source-only
else
    make
fi

# 3. build all common components
cd $BASE_DIR/common/
make clean && make

# 4. build language-specific component
# 4.1 clang

# 4.2 java
cd $BASE_DIR/langspec/java
./build.sh

# 4.3 python
cd $BASE_DIR/langspec/python
./pybuild.sh

# 5 tools
cd $BASE_DIR/tool/BBstat
make clean && make
