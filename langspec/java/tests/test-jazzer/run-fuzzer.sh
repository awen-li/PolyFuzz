
target=test-jazzer.jar

# link jazzer to current fuzzing directory
ln -s $JAZZER_ROOT/jazzer jazzer
ln -s $JAZZER_ROOT/jazzer_agent_deploy.jar jazzer_agent_deploy.jar
ln -s $JAZZER_ROOT/jazzer_api_deploy.jar jazzer_api_deploy.jar

python $BENCH/script/popen_log.py "./jazzer --instrumentation_includes=tests.Main --cp=$target --target_class=tests.Main ./seeds" &

