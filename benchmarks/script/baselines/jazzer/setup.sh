
BASE_DIR=`pwd`


if [ ! -n "$JAZZER_ROOT" ]; then
    export JAZZER_ROOT=$BASE_DIR/jazzer_root
	echo "export JAZZER_ROOT=$BASE_DIR/jazzer_root" >> /root/.bashrc
fi

