cd jsoup/

tar -zxvf jazzer_release.tar.gz

nohup ./jazzer --cp=jsoup.jar --autofuzz=org.jsoup.Jsoup::parse > full.log 2>&1 &

python extract_log.py

