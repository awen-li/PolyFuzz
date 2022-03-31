cd ../

#build docker image
python3 infra/helper.py build_image bleach

#build fuzz targets
python3 infra/helper.py build_fuzzers --sanitizer address bleach

cd projects/bleach/

pip3 install hypothesis

python3 sanitize_fuzzer.py