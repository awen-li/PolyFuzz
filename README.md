# POLYFUZZ: Holistic Greybox Fuzzing of Multi-Language Systems


# Introduction
we present PolyFuzz, a greybox fuzzer that holistically fuzzes a given multi-language system through cross-language coverage feedback and explicit modeling of the semantic relationships between inputs and branch predicates. PolyFuzz is extensible for supporting multilingual code using different language combinations and has been implemented for C/C++, Python, Java, and their combinations.

```
PolyFuzz
├── AFLplusplus       --------------  the core fuzzing agent
├── baseline          --------------  configurations and scripts for baselines
├── benchmarks        --------------  configurations, scripts and drivers for benchmarks
├── common            --------------  common modules
│   ├── DynTrace      --------------  dynamic tracing library
│   ├── IGC           --------------  instrumentation guidance computation
│   ├── SASG          --------------  sensitivity analysis and seed generation
│   └── shmqueue      --------------  shared memory queue
├── documents         --------------  some DOCs during the development
├── langspec          --------------  language specific analysis
│   ├── clang         --------------  analysis for C 
│   ├── java          --------------  analysis for Java
│   └── python        --------------  analysis for Python
└── tool
```

# Installation

## 1. Requirements
#### 1.1 Setup the environment manually
PolyFuzz is tested on Ubuntu18.04, LLVM11.0, Soot4.3.0, Python3.8/9 (and Python3-dev), and OpenJDK 8/11.

#### 1.2 Reuse the environment from docker image (recommanded)
We build a [docker image](https://hub.docker.com/repository/registry-1.docker.io/daybreak2019/polyfuzz/tags?page=1&ordering=last_updated) with all dependences ready (i.e., all the dependencies required for running PolyFuzz itself; 
for subject systems (benchmarks), we provides scripts to setup the environments under benchmarks/script.<br>
Please use the command ```docker pull daybreak2019/polyfuzz:v1.1``` to pull the image to local storage.


## 2. Build PolyFuzz
After cloning the code from GitHub, using the following command to build the whole project.
```
cd PolyFuzz && . buid.sh
```


## 3. Usage

#### 3.1 Steps for fuzzing C programs

Build the C program with the following environment variable set:
```
export CC="afl-cc -fPIC -lxFuzztrace"
export CXX="afl-c++ -fPIC -lxFuzztrace"
```
An [example](https://github.com/Daybreak2019/xFuzz/tree/main/benchmarks/script/single-benches/c/bind9)  for C program

#### 3.2 Steps for fuzzing Python-C programs

##### 3.2.1 Setup the program with AFL++ (instrument C program)
Add following code on the top of setup.py in targets
```
import os
os.environ["CC"]  = "afl-cc"
os.environ["CXX"] = "afl-c++"
```
##### 3.2.2 Parse python code summary
```
python -m parser [python code dir]
```
A xml "py_summary.xml" will be generated in the specified dir, it should be placed with the drivers.
An [example](https://github.com/Daybreak2019/xFuzz/tree/main/benchmarks/script/multi-benches/Pillow)  for Python-C program

#### 3.3 Steps for fuzzing Java-C programs
```
java -cp .:$JavaCovPCG/JavaCovPCG.jar JCovPCG.Main -t <class-dir>
```

An [example](https://github.com/Daybreak2019/xFuzz/tree/main/benchmarks/script/multi-benches/jansi)  for Java-C program


## 4. Vulnerabilities detected on real-world programs
PolyFuzz got 5 CVEs assigned on 5 multi-language real-world programs:
CVE-2022-34070, CVE-2022-34072, CVE-2022-34073, CVE-2022-34074, CVE-2022-34075

Refer to [Vulnerability](https://github.com/Daybreak2019/PolyFuzz/tree/main/Vulnerability) for details.
