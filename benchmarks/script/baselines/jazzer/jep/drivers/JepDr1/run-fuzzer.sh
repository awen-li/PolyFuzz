#!/bin/sh

target=JepDr1.jar

# link jazzer to current fuzzing directory
ln -s $JAZZER_ROOT/jazzer jazzer
ln -s $JAZZER_ROOT/jazzer_agent_deploy.jar jazzer_agent_deploy.jar
ln -s $JAZZER_ROOT/jazzer_api_deploy.jar jazzer_api_deploy.jar

export JEP_PATH=$JepPath/jep-4.0.3.jar


python $BENCH/script/popen_log.py "./jazzer --instrumentation_includes=jep.** --cp=$target:$JEP_PATH --target_class=JepDr.JepDrOne ./tests" &


