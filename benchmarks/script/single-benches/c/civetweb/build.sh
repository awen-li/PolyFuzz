

export ROOT=`pwd`
export target=civetweb

#dependences

function collect_branchs ()
{
	driver=$1
	
	if [ -f "$ROOT/drivers/$driver/branch_vars.bv" ]; then
		rm $ROOT/drivers/$driver/branch_vars.bv
	fi
	
	ALL_BRANCHS=`find $ROOT/$target -name branch_vars.bv`
	echo "@@@@@@@@@ ALL_BRANCHES -----> $ALL_BRANCHS"
	for branch in $ALL_BRANCHS
	do
		cat $branch >> $ROOT/drivers/$driver/branch_vars.bv
		rm $branch
	done
}


function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/civetweb/civetweb.git
	
	cp Makefile $target/
    cd $target/
    
    ALL_DRIVERS=`ls $ROOT/drivers`
    echo $ALL_DRIVERS
	for driver in $ALL_DRIVERS
	do
		if [ ! -d "$ROOT/drivers/$driver" ]; then
			continue
	    fi
	    
	    echo "****************************************"
	    echo "** compiling driver $driver ..........**"
	    echo "****************************************"
	    
		cp $ROOT/drivers/$driver/$driver.c ./fuzztest/fuzzmain.c
    	make TEST_FUZZ=1

    	collect_branchs $driver  	
    	cp civetweb $ROOT/drivers/$driver/driver
	done
	
	cd -
}


cd $ROOT
compile

cd $ROOT
