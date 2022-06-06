cd ../

#build docker image
python infra/helper.py build_image bleach

#build fuzz targets
python infra/helper.py build_fuzzers --sanitizer address bleach

cd projects/bleach/

pip3 install atheris

pip3 install hypothesis

nohup python -u sanitize_fuzzer.py > full.log 2>&1 &

python extract_log.py