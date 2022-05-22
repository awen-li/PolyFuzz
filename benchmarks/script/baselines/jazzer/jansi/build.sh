

export ROOT=`cd ../../../../ && pwd`
export target=jansi

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/fusesource/jansi.git

	pushd $target
	
	cp $ROOT/script/$target/Makefile $ROOT/$target
    make 
	
	mvn clean package
	
	popd
}


cd $ROOT
compile


