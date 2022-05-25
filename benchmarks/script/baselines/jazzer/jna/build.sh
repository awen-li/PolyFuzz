

export ROOT=`cd ../../../../ && pwd`
export target=jna

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/java-native-access/jna.git
	
	JAVA_8=`echo $JAVA_HOME | grep java-8`
	if [ ! -n "$JAVA_8" ]; then
		export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
		update-java-alternatives --set java-1.8.0-openjdk-amd64
	fi

	cd $target
	
	# compile native
	cd native
	ant
	cd ..
    
	# compile java
	ant
}


cd $ROOT
compile


