# xFuzz
POLYFUZZ: Holistic Greybox Fuzzing of Multi-Language Systems

# Introduction
```
PolyFuzz
+-- AFLplusplus                 ---------------   the core fuzzing agent
+-- baseline                    ---------------   evaluation scripts of three baselines: Atheris, Jazzer and Honggfuzz
+-- benchmarks                  ---------------   drivers&scripts of multilingual bencharks for PolyFuzz, Atheris, Jazzer, and single-language drivers for PolyFuzz
+-- build.sh                    ---------------   the build script for the whole project
+-- common                      ---------------   implementation of common library
¦   +-- ctrace                  ---------------   dynamic tracing
¦   +-- pcgInstrm               ---------------   coverage guidance computation
¦   +-- ple                     ---------------   sensitivity analysis engine
¦   +-- shmqueue                ---------------   shared memory queue for dynamic event tracing
+-- langspec                    ---------------   language specific analysis
¦   +-- clang                   ---------------   for c
¦   +-- java                    ---------------   for java
¦   +-- python                  ---------------   for python
+-- NewVulnerabilities.pdf      ---------------   new vulnerabilities discovered by PolyFuzz
+-- tool                        ---------------   internal tool set
```

# Build xFuzz
### Use following script to build the whole system
```
. buid.sh
```

# Steps for fuzzing C programs
```
export CC="afl-cc -fPIC -lxFuzztrace"
export CXX="afl-c++ -fPIC -lxFuzztrace"
```
An [example](https://github.com/Daybreak2019/xFuzz/tree/main/benchmarks/script/single-benches/c/bind9)  for C program

# Steps for fuzzing Python-C programs

### Setup the program with AFL++ (instrument C program)
Add following code on the top of setup.py in targets
```
import os
os.environ["CC"]  = "afl-cc"
os.environ["CXX"] = "afl-c++"
```
### Parse python code summary
```
python -m parser [python code dir]
```
A xml "py_summary.xml" will be generated in the specified dir, it should be placed with the drivers.
An [example](https://github.com/Daybreak2019/xFuzz/tree/main/benchmarks/script/multi-benches/Pillow)  for Python-C program

# Steps for fuzzing Java-C programs
```
java -cp .:$JavaCovPCG/JavaCovPCG.jar JCovPCG.Main -t <class-dir>
```

An [example](https://github.com/Daybreak2019/xFuzz/tree/main/benchmarks/script/multi-benches/jansi)  for Java-C program
