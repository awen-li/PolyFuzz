



export ROOT=`pwd`
export target=javaparser

function instrument_java ()
{
	inst_dir=$1
	jar_name=$2
	
	if [ -d "$inst_dir" ]; then
		rm -rf $inst_dir
	fi
	
	mkdir $inst_dir
	cd $inst_dir
	jar -xvf ../app/$jar_name
	
	echo "8" > $inst_dir/INTERAL_LOC

	java -cp .:$JavaCovPCG/JavaCovPCG.jar JCovPCG.Main -t .
	cp sootOutput/* -rf .
	rm -rf sootOutput
    
    mv EXTERNAL_LOC ../
    rm INTERAL_LOC
    mv branch_vars.bv ../
    
	jar -cvfm $jar_name META-INF/MANIFEST.MF *
	chmod a+x $jar_name
	cp $jar_name ../
}

# switch to java11
#update-java-alternatives -s /usr/lib/jvm/java-1.11.0-openjdk-amd64
#export JAVA_HOME=/usr/lib/jvm/java-1.11.0-openjdk-amd64
unset JAVA_TOOL_OPTIONS

function compile_source ()
{
	if [ -d "$target" ]; then
		rm -rf $target
    fi
    
    git clone https://github.com/javaparser/javaparser.git
    cd $target
    mvn clean install
    
    mv javaparser-core/javaparser-core-*-SNAPSHOT.jar ../app/javaparser.jar -f
    cd -
}

#compile_source
if [ "$1" == "build" ]; then
	compile_source
fi

# instrument java
jar_dir=$ROOT/$target-instm
instrument_java $jar_dir "javaparser.jar"


