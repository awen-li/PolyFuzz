
BASE_DIR=`pwd`

# 1. dependences in common
if [ ! -d "/usr/include/ctrace" ]; then 
    mkdir /usr/include/ctrace 
fi
cp $BASE_DIR/common/ctrace/include/* /usr/include/ctrace/ -rf
cd $BASE_DIR/common/shmqueue && make clean && make
cd $BASE_DIR/common/ple && make && make


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
cd $BASE_DIR/tool/javawrapper
make clean && make
cd $BASE_DIR/tool/Perfget && ./install.sh
cp $BASE_DIR/tool/delshm.sh /usr/bin/
cp $BASE_DIR/tool/PyVersion.sh /usr/bin/
cd $BASE_DIR

# init environment
export JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF8

if [ ! -n "$JAVA_HOME" ]; then
    export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
	echo "export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64" >> /root/.bashrc
fi

if [ ! -n "$BENCH" ]; then
    export BENCH=$BASE_DIR/benchmarks
	echo "export BENCH=$BASE_DIR/benchmarks" >> /root/.bashrc
fi

if [ ! -n "$JavaCovPCG" ]; then
    export JavaCovPCG=/usr/lib/JavaCovPCG
	echo "export JavaCovPCG=/usr/lib/JavaCovPCG" >> /root/.bashrc
fi

if [ ! -n "$JepPath" ]; then
    export JepPath=$(sh /usr/bin/PyVersion.sh)/site-packages/jep
	echo "export JepPath=$(sh /usr/bin/PyVersion.sh)/site-packages/jep" >> /root/.bashrc
fi

if [ ! -n "$LD_LIBRARY_PATH" ]; then
	echo "export LD_LIBRARY_PATH=$JepPath:$LD_LIBRARY_PATH" >> /root/.bashrc
	export LD_LIBRARY_PATH=$JepPath:$LD_LIBRARY_PATH
fi