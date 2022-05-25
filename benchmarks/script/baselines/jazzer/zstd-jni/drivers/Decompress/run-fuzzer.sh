#!/bin/sh

target=Decompress.jar

# link jazzer to current fuzzing directory
ln -s $JAZZER_ROOT/jazzer jazzer
ln -s $JAZZER_ROOT/jazzer_agent_deploy.jar jazzer_agent_deploy.jar
ln -s $JAZZER_ROOT/jazzer_api_deploy.jar jazzer_api_deploy.jar

JAR_PATH=`ls $BENCH/zstd-jni/target/zstd-jni*.jar`
export ZSTD_PATH=$JAR_PATH

python $BENCH/script/popen_log.py "./jazzer --cp=$target:$ZSTD_PATH --target_class=DcmpZstd.DeCompress ./tests" &

