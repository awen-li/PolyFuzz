#!/bin/sh

./jazzer --cp=jsoup.jar --instrumentation_includes=org.jsoup.** --target_class="HtmlFuzzer" seeds_corpus --coverage_report="report.log"
