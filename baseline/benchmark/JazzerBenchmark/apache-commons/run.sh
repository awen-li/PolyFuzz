#!/bin/sh

./jazzer --cp=commons-compress.jar --instrumentation_includes=org.apache.commons.compress.archivers.zip.ZipFile**:org.apache.commons.compress.utils.SeekableInMemoryByteChannel** --target_class="CompressZipFuzzer" seeds_corpus --coverage_report="report.log"
