

export ROOT=`cd ../../../../ && pwd`
export target=zstd-jni

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/luben/zstd-jni.git

	pushd $target
	
	export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
	update-java-alternatives --set java-1.8.0-openjdk-amd64
	
	./sbt compile package
	
	popd
}


cd $ROOT
compile


