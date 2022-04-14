cd ../

#build docker image
python infra/helper.py build_image pygments

#build fuzz targets
python infra/helper.py build_fuzzers --sanitizer address pygments

cd projects/pygments/

pip3 install hypothesis

nohup python -u fuzz_guesser.py > full.log 2>&1 &

python extract_log.py