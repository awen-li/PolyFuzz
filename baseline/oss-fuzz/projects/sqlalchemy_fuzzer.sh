cd ../

#build docker image
python infra/helper.py build_image sqlalchemy

#build fuzz targets
python infra/helper.py build_fuzzers --sanitizer address sqlalchemy

cd projects/sqlalchemy/

pip3 install hypothesis

nohup python -u sqlalchemy_fuzzer.py > full.log 2>&1 &

nohup python extract_log.py