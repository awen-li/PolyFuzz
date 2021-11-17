# xFuzz
a data flow sensitive cross-langauge fuzzer

# Introduction

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
