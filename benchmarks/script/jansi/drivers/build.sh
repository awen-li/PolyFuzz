#!/bin/bash  
  
Root=`pwd`

if [ ! -n "$JavaCovPCG" ]; then
	echo "set JavaCovPCG first!"
	exit 0
fi


export AERON_PATH=$BENCH/aeron/aeron-all/build/libs


function deplibs ()
{
    apt install maven
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

function instrument ()
{
	TARGET=$1
	
	cd $TARGET
	cp /usr/lib/JavaCovPCG/* -rf ./	
	java -jar JavaCovPCG.jar -d dep -t bin/
	cp sootOutput/* -rf bin/
	cd -
}

function pack ()
{
	TARGET=$1
	
	JAVA_CLASS=$Root/$TARGET/bin
	
	cd $JAVA_CLASS  
    jar -cvfm $Root/$TARGET/$TARGET.jar $Root/$TARGET/MANIFEST.MF *
    chmod a+x $Root/$TARGET/$TARGET.jar
    cd -
}


ALL_TESTS=`ls` 
for JT in $ALL_TESTS
do
	if [ ! -d "$JT" ]; then
		continue
    fi
    
    echo
    echo "==================================================="
    echo "                  start compile $JT                "
    echo "==================================================="
    echo
    
    compile $JT
    #instrument $JT
    pack $JT
done
  
cd $Root 