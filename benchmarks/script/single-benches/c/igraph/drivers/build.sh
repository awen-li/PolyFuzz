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
    cd $JT/tests && tar -xzf ../seed_corpus.tar.gz  && cd -

    cp $FUZZ_HOME/lib     $JT/ -rf
    cp $FUZZ_HOME/include $JT/ -rf

    cd $JT && make clean && make && cd -
    cp branch_vars.bv $JT/
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$Root/$JT/lib

done
  
cd $Root