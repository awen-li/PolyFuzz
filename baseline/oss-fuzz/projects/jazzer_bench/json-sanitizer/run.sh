#!/bin/sh

#./jazzer --cp=json-sanitizer.jar --autofuzz=com.google.json.JsonSanitizer::sanitize

./jazzer --cp=json-sanitizerV2.jar --instrumentation_includes=com.google.json.** --target_class="IdempotenceFuzzer" corpus --coverage_report="report.log"

#./jazzer --cp=json-sanitizerV2.jar --instrumentation_includes=com.google.json.** --target_class="ValidJsonFuzzer" --coverage_report="report.log"

#./jazzer --cp=json-sanitizerV2.jar --target_class="ValidJsonFuzzer" --coverage_report="report.log"
