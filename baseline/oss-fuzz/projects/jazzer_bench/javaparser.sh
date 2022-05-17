cd javaparser/

tar -zxvf jazzer_release.tar.gz

nohup --cp=javaparser.jar --autofuzz="com.github.javaparser.JavaParser::parse(java.io.InputStream)" > full.log 2>&1 &

python extract_log.py

