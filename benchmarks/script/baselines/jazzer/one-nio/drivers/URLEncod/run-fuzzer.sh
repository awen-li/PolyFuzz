#!/bin/sh

target=URLEncod.jar

# link jazzer to current fuzzing directory
ln -s $JAZZER_ROOT/jazzer jazzer
ln -s $JAZZER_ROOT/jazzer_agent_deploy.jar jazzer_agent_deploy.jar
ln -s $JAZZER_ROOT/jazzer_api_deploy.jar jazzer_api_deploy.jar

export ONENIO_PATH=$BENCH/one-nio/build/one-nio.jar:$BENCH/one-nio/lib/asm-9.2.jar:$BENCH/one-nio/lib/commons-logging-1.2.jar::$BENCH/one-nio/lib/log4j-1.2.17.jar

python $BENCH/script/popen_log.py "./jazzer --instrumentation_includes=one.nio.**  --cp=$target:$ONENIO_PATH --target_class=URLEncodDrv.URLEncodDrv ./tests" &

