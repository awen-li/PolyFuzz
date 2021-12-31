

target=immutables
task=$1

cd ../../

if [ "$task" == "clone" ]; then
	git clone https://github.com/numpy/numpy.git
	git submodule update --init
fi

if [ -d "$target/build" ]; then
	rm -rf $target/build
fi

# 1. py summary
python -m parser -E ./script/$target/ExpList ./$target


# 2. instrument C extersions
cp script/$target/setup-afl.py $target/
cd $target/
python setup-afl.py install
