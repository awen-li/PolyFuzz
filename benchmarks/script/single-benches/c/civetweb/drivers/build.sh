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
    	cd $JT/tests && tar -xzf ../seed_corpus.tar.gz
    fi

done
  
cd $Root 