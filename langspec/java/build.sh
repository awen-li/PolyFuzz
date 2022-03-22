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
	ALL_LIBS=`find $LIB_DIR -name "*.jar"`
	for lib in $ALL_LIBS
	do
		DEPLIBS=$DEPLIBS":"$lib
	done
	
	echo $DEPLIBS
}

function compileNative()
{
	TARGET=$1
	if [ ! -n "$TARGET" ]; then
		echo "Target needs be specificed for compilation!"
		exit 0
	fi
	
	cd $Root/$TARGET/src/jni
	make -f makefile_dynt clean && make -f makefile_dynt
	make -f makefile_pcg clean  && make -f makefile_pcg
}
  
function compileJava()
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
	echo "@@@ dependent libs: $DEPENDENT_LIBS"
    javac -d $JAVA_CLASS -encoding utf-8 -cp .:$DEPENDENT_LIBS -g -sourcepath $JAVA_SOURCE @$JAVA_SOURCE/sources.list  
    
  
    cd $JAVA_CLASS  
    jar -cvfm $Root/$TARGET/$TARGET.jar $Root/$TARGET/MANIFEST.MF *
    chmod a+x $Root/$TARGET/$TARGET.jar  
}  

function InstallJavaCovPCG()
{
	TARGET=$1
	INSTALL_DIR="/usr/lib/$TARGET"
	if [ ! -d "$INSTALL_DIR" ]; then
	    mkdir $INSTALL_DIR
	fi
	
	cp $Root/$TARGET/$TARGET.jar $INSTALL_DIR/
	cp $Root/$TARGET/lib -rf $INSTALL_DIR/
}

TARGET="JavaCovPCG"
compileNative     $TARGET
compileJava       $TARGET
InstallJavaCovPCG $TARGET
exit 0  