#!/bin/bash  
  
Root=`pwd`

ALL_TESTS=`ls` 
for JT in $ALL_TESTS
do
	if [ ! -d "$JT" ]; then
		continue
    fi
    
    if [ ! -d "$JT/tests" ]; then
    	mkdir $JT/tests
    fi
    cd $JT/tests && tar -xzf ../seed_corpus.tar.gz && cd -
    
    if [ ! -d "$JT/lib" ]; then
    	mkdir $JT/lib
    fi
    
    cp $FUZZ_HOME/lib/* $JT/lib/ -rf
    cp $FUZZ_HOME/include/* $JT/include/ -rf
    
    cd $JT && make clean && make && cd -
    cp branch_vars.bv $JT/
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$Root/$JT/lib

done
  
