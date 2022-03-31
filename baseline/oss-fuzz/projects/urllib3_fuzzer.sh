cd ../

#build docker image
python3 infra/helper.py build_image urllib3

#build fuzz targets
python3 infra/helper.py build_fuzzers --sanitizer address urllib3

cd projects/urllib3

pip3 install hypothesis

python3 fuzz_urlparse.py