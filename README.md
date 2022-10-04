# xFuzz
POLYFUZZ: Holistic Greybox Fuzzing of Multi-Language Systems

# Introduction
```
PolyFuzz
├── AFLplusplus       --------------  the core fuzzing agent
├── baseline          --------------  configurations and scripts for baselines
├── benchmarks        --------------  configurations and scripts for benchmarks
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

# Build PolyFuzz
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
