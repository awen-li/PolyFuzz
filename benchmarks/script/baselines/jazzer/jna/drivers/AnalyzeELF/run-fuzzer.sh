#!/bin/sh

target=AnalyzeELF.jar

# link jazzer to current fuzzing directory
ln -s $JAZZER_ROOT/jazzer jazzer
ln -s $JAZZER_ROOT/jazzer_agent_deploy.jar jazzer_agent_deploy.jar
ln -s $JAZZER_ROOT/jazzer_api_deploy.jar jazzer_api_deploy.jar

export JAN_PATH=$BENCH/jansi/target/jansi-2.4.1-SNAPSHOT.jar


python $BENCH/script/popen_log.py "./jazzer --cp=$target:$JAN_PATH --target_class=AnalyzeELF.AnalyzeELF ./tests" &


