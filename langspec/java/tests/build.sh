#!/bin/bash  
  
Root=`pwd`

function deplibs ()
{
	LIB_DIR=$1
	if [ ! -d "$LIB_DIR" ]; then
		echo ""
		return
	fi
	
	DEPLIBS=""
	ALL_LIBS=`find $LIB_DIR`
	for lib in $ALL_LIBS
	do
		DEPLIBS=$DEPLIBS":"$lib
	done
	
	echo $DEPLIBS
}
  
function compile()
{
    TARGET=$1
    if [ ! -n "$TARGET" ]; then
        echo "Target needs be specificed for compilation!"
        exit 0
    fi
	
    JAVA_SOURCE=$Root/$TARGET/src
    JAVA_LIB=$Root/$TARGET/lib
    JAVA_CLASS=$Root/$TARGET/bin

    find $JAVA_SOURCE -name "*.java" > $JAVA_SOURCE/sources.list  
    cat $JAVA_SOURCE/sources.list
   
    if [ -d "$JAVA_CLASS" ]; then
    	rm -rf $JAVA_CLASS
    fi
    mkdir -p $JAVA_CLASS 

	DEPENDENT_LIBS=$(deplibs $JAVA_LIB)
    javac -d $JAVA_CLASS -encoding utf-8 -cp .:$DEPENDENT_LIBS -g -sourcepath $JAVA_SOURCE @$JAVA_SOURCE/sources.list  
}

function pack ()
{
	TARGET=$1
	
	JAVA_CLASS=$Root/$TARGET/bin
	
	cd $JAVA_CLASS  
    jar -cvfm $Root/$TARGET/$TARGET.jar $Root/$TARGET/MANIFEST.MF *
    sudo chmod a+x $Root/$TARGET/$TARGET.jar  
}

function instrument ()
{
	TARGET=$1
	
	cd $TARGET
	if [ ! -f "JavaCovPCG.jar" ]; then
	    cp /usr/lib/JavaCovPCG/* -rf ./
	fi
	
	java -jar JavaCovPCG.jar -t bin/
}

ACTION=$1
ALL_TESTS=`ls` 
for JT in $ALL_TESTS
do
	if [ ! -d "$JT" ]; then
		continue
    fi
    
    echo "start compile $JT"
    
    compile $JT  
    instrument $JT
    pack $JT

	
done
  

exit 0  