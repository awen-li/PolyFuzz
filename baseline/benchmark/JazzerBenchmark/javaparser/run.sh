#!/bin/sh

./jazzer --cp=javaparser.jar --instrumentation_includes=com.github.javaparser.** --target_class="parseFuzzer" seeds_corpus --coverage_report="report.log"
