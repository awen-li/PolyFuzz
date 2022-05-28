



export ROOT=`pwd`
export target=zxing

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
	
	if [ -d "../EXTERNAL_LOC" ]; then
	    cat ../EXTERNAL_LOC > $inst_dir/INTERAL_LOC
	else
	    echo "8" > $inst_dir/INTERAL_LOC
	fi
	
	echo "../app/jsr305-3.0.2.jar" > dep
	java -cp .:$JavaCovPCG/JavaCovPCG.jar: JCovPCG.Main -d dep -t .
	cp sootOutput/* -rf .
	rm -rf sootOutput
    
    mv EXTERNAL_LOC ../
    rm INTERAL_LOC
    mv branch_vars.bv ../
    
	jar -cvfm $jar_name META-INF/MANIFEST.MF *
	chmod a+x $jar_name
	cp $jar_name ../
	cd -
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
    
    git clone https://github.com/zxing/zxing.git
    cd $target
    mvn clean install
    
    mv core/target/core-*-SNAPSHOT.jar ../app/zxing.jar -f
    cd -
}

#compile_source
if [ "$1" == "build" ]; then
	compile_source
fi

# instrument java
jar_dir=$ROOT/$target-instm
instrument_java $jar_dir "zxing.jar"


cd $ROOT

