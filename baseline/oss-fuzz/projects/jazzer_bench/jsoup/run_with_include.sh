#!/bin/sh

./jazzer --cp=commons-compress.jar --instrumentation_includes=CompressZipFuzzer** --target_class="CompressZipFuzzer" seeds_corpus --coverage_report="report.log"
