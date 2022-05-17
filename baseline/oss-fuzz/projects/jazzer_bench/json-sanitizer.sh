cd json-sanitizer/

tar -zxvf jazzer_release.tar.gz

nohup ./jazzer --cp=json-sanitizer-1.2.3.jar --autofuzz=com.google.json.JsonSanitizer::sanitize > full.log 2>&1 &

python extract_log.py

