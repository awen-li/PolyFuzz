# xFuzz
a data flow sensitive cross-langauge fuzzer

# Introduction
```
xFuzz
├── ADUC            ======  ADUC learning engine
├── AFLplusplus     ======  AFL++, C instrumentation and coverage report
├── common          ======  common support modules
│   ├── ctrace      ------  dynamic tracing library, memory management for event queue
│   └── cvgopt      ------  optimization library for coverage-instrumentation
├── documents
├── langspec        ======  Language specfic components
│   ├── clang       ------  C instrumentation library
│   ├── java        ------  Java instrumentation library
│   └── python      ------  Python parser and instrumentation library
└── tool            ======  thirdparties and demos
    ├── PyTrace
    └── PyTraceBind
```

# Build xFuzz
### Use following script to build the whole system
```
./buid.sh
```
### Add (yourpath)/xFuzz/AFLplusplus to environment (PATH)
```
export PATH=([yourpath)/xFuzz/AFLplusplus:$PATH
```

# Steps for fuzzing Python-C programs

### Setup the program with AFL++ (instrument C program)
Add following code on the top of setup.py in targets
```
import os
os.environ["CC"]  = "afl-cc"
os.environ["CXX"] = "afl-cc++"
```

### Parse python code summary
```
python -m parser [python code dir]
```
A xml "py_summary.xml" will be generated in the specified dir, it should be placed with the drivers. 

### Prepare driver, tests
As shown in the [example](https://github.com/Daybreak2019/xFuzz/tree/main/benchmarks/mongo)
The keys to write the driver is to import the library "pyprob"

### Run the fuzzing
Use a similar script as the run-fuzzer.sh in [example](https://github.com/Daybreak2019/xFuzz/tree/main/benchmarks/mongo)
