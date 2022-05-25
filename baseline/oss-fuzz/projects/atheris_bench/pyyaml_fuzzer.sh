cd ../

#build docker image
python infra/helper.py build_image pyyaml

#build fuzz targets
python infra/helper.py build_fuzzers --sanitizer address pyyaml

cd projects/pyyaml

pip3 install hypothesis

nohup python -u fuzz_loader.py > full.log 2>&1 &

python extract_log.py