#!/bin/sh

#./jazzer --cp=json-sanitizer.jar --autofuzz=com.google.json.JsonSanitizer::sanitize

./jazzer --cp=json-sanitizerV2.jar --instrumentation_includes=com.google.json.JsonSanitizer.** --target_class="ValidJsonFuzzer" corpus --coverage_report="report.log"
