cd zxing/

tar -zxvf jazzer_release.tar.gz

nohup ./jazzer --cp=zxing.jar --autofuzz="com.google.zxing.MultiFormatReader::decode" > full.log 2>&1 &

python extract_log.py

