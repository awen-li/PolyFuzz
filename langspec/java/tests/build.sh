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
    
    # compile JNI if exists
    if [ ! -d "$JAVA_SOURCE/jni" ]; then
        return
    fi
    cd $JAVA_SOURCE/jni
    make clean && make
    cd -
}

function pack ()
{
	TARGET=$1
	
	JAVA_CLASS=$Root/$TARGET/bin
	
	cd $JAVA_CLASS  
    jar -cvfm $Root/$TARGET/$TARGET.jar $Root/$TARGET/MANIFEST.MF *
    sudo chmod a+x $Root/$TARGET/$TARGET.jar
    cd -
}

function instrument ()
{
	TARGET=$1
	
	cd $TARGET
	cp /usr/lib/JavaCovPCG/* -rf ./	
	java -jar JavaCovPCG.jar -t bin/
	cp sootOutput/tests -rf bin/
	cd -
}

ACTION=$1
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
    
    if [ "$ACTION" != "" ] && [ "$ACTION" != "$JT" ]; then
    	continue
    fi
    
    compile $JT  
    instrument $JT
    pack $JT

	
done
  

exit 0  