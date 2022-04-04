cd ../

#build docker image
python infra/helper.py build_image urllib3

#build fuzz targets
python infra/helper.py build_fuzzers --sanitizer address urllib3

cd projects/urllib3

pip3 install hypothesis

nohup python -u fuzz_urlparse.py > full.log 2>&1 &

nohup python extract_log.py