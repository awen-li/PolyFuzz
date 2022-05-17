cd json-sanitizer/

tar -zxvf jazzer_release.tar.gz

nohup ./jazzer --cp=commons-compress.jar --autofuzz="org.apache.commons.compress.archivers.zip.ZipFile::getEntries" > full.log 2>&1 &

python extract_log.py

