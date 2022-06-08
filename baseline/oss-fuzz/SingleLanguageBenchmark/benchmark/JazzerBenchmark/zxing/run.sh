#!/bin/sh

./jazzer --cp=zxing.jar --instrumentation_includes=com.google.zxing.** --target_class="MultiFormatDecodeFuzzer" seeds_corpus --coverage_report="report.log"
