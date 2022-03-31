cd ../

#build docker image
python3 infra/helper.py build_image sqlalchemy

#build fuzz targets
python3 infra/helper.py build_fuzzers --sanitizer address sqlalchemy

cd projects/sqlalchemy/

pip3 install hypothesis

python3 sqlalchemy_fuzzer.py