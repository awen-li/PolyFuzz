#!/bin/bash  
  
Root=`pwd`


export JANSI_PATH=./jansi-2.4.1-SNAPSHOT.jar

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

    javac -d $JAVA_CLASS -encoding utf-8 -cp .:$JANSI_PATH -g -sourcepath $JAVA_SOURCE @$JAVA_SOURCE/sources.list
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
    pack $JT
done
  
cd $Root 