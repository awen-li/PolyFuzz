



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

# instrument java
jar_dir=$ROOT/$target-instm
instrument_java $jar_dir "javaparser.jar"


