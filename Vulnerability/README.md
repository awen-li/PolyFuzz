# Vulnerabilities detected by polyfuzz
We evaluate polyfuzz on several popular open-source projects developed mainly in 10 Python-C programs, 5 Java-C programs, and 15 single-language programs (5 respectively in C, Python, and Java).
Eventually, 14 vulnerabilities in 8 projects below are validated to be exploitable, and corresponding PoCs are attached.

## [Ultrajson](https://github.com/ultrajson/ultrajson): [Vendor]ultrajson
#### [Vulnerability]: Segment fault
**Affected version**: version <= 5.2.0 <br>
**Description**: With carefully constructed inputs, NULL pointer reference can happen and cause segment fault. This allows attackers to conduct DoS attacks by construct specific inputs.<br>
**Exploitation**: PoC: [ujson_poc.py](https://github.com/baltsers/polyfuzz/blob/master/ultrajson/bug1/ujson_poc.py) with [Input](https://github.com/baltsers/polyfuzz/blob/master/ultrajson/bug1/input) and [Output](https://github.com/baltsers/polyfuzz/blob/master/ultrajson/bug1/crash-info.txt).<br>

## [Pyyaml](https://github.com/yaml/pyyaml): [Vendor]yaml.org
#### [Vulnerability]: Recursion Error
**Affected version**: version <= 6.0 <br>
**Description**: With carefully constructed inputs, Recursion Error can happen. This allows attackers to conduct DoS attacks by construct specific inputs.<br>
**Exploitation**: PoC: [poc_load.py](https://github.com/baltsers/polyfuzz/blob/master/pyyaml/poc_load.py) with [Input](https://github.com/baltsers/polyfuzz/blob/master/pyyaml/test) and [Output](https://github.com/baltsers/polyfuzz/blob/master/pyyaml/pyyaml.log).<br>

## [Jansi](https://github.com/fusesource/jansi): [Vendor]fusesource.com
#### [Vulnerability]: Out of Memory
**Affected version**: version <= 2.4.0 <br>
**Description**: With carefully constructed inputs, Out of Memory can happen. This allows attackers to conduct DoS attacks by construct specific inputs.<br>
**Exploitation**: PoC: [OutStream](https://github.com/baltsers/polyfuzz/tree/master/jansi/OutStream) with [Input](https://github.com/baltsers/polyfuzz/blob/master/jansi/OutStream/tests/oom-case).<br>

## [Pillow](https://github.com/python-pillow/Pillow): [Vendor]python-pillow.org
#### [Vulnerability]: Out of Memory
**Affected version**: version <= 9.1.1 <br>
**Description**: With carefully constructed inputs, out of memory can happen in API convert. This allows attackers to conduct DoS attacks by construct specific inputs<br>
**Exploitation**: PoC: [poc_fig_process.py](https://github.com/baltsers/polyfuzz/blob/master/pillow/poc_fig_process.py) with [Input](https://github.com/baltsers/polyfuzz/blob/master/pillow/oom-case).<br>

## [Libsmbios](https://github.com/dell/libsmbios): [Vendor]Dell
#### [Vulnerability]: Segment fault
**Affected version**: version <= 2.4.3 <br>
**Description**: With carefully constructed inputs, libsmbios can crash with bus error. This allows attackers to conduct DoS attacks by construct specific inputs<br>
**Exploitation**: PoC: [poc_op_mem.py](https://github.com/baltsers/polyfuzz/blob/master/libsmbios/poc_op_mem.py) with [Input](https://github.com/baltsers/polyfuzz/blob/master/libsmbios/crash-seed) and [Output](https://github.com/baltsers/polyfuzz/blob/master/libsmbios/crash-stackinfo.txt).<br>

## [Javaparser](https://github.com/javaparser/javaparser): [Vendor]javaparser.org
#### [Vulnerability]: JVM hangs
**Affected version**: version <= 3.24.2 <br>
**Description**: With carefully constructed inputs, JVM hangs. This allows attackers to conduct DoS attacks by construct specific inputs<br>
**Exploitation**: PoC: [jparser](https://github.com/baltsers/polyfuzz/tree/master/javaparser) with [Input](https://github.com/baltsers/polyfuzz/blob/master/javaparser/test) and [Output](https://github.com/baltsers/polyfuzz/blob/master/javaparser/javaparser.log).<br>

## [Aubio](https://github.com/aubio/aubio): [Vendor]aubio.org
#### [Vulnerability]: Memory Leak
**Affected version**: version <= 0.4.9 <br>
**Description**: With carefully constructed inputs, memory leak could happen during continuous running.<br>
**Exploitation**: PoC: [filter-test.py](https://github.com/baltsers/polyfuzz/blob/master/aubio/filter-test.py) with [Input](https://github.com/baltsers/polyfuzz/blob/master/aubio/case-abnormal) and [Output](https://github.com/baltsers/polyfuzz/blob/master/aubio/log.txt).<br>

## [Bottleneck](https://github.com/pydata/bottleneck): [Vendor]PyData
#### [Vulnerability-1]: Segment fault
**Affected version**: version <= 1.3.4 <br>
**Description**: With carefully constructed inputs, the API median can crash with segment fault. This allows attackers to conduct DoS attacks by construct specific inputs. <br>
**Exploitation**: PoC: [random_shape.py](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/random_shape.py) and [Output](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/crash_info-median.txt).<br>
With 7 inputs: [input1](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input1),  [input2](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input2),  [input3](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input3),  [input4](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input4),  [input5](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input5),  [input6](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input6),  [input7](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input7)

#### [Vulnerability-2]: Segment fault
**Affected version**: version <= 1.3.4 <br>
**Description**: With carefully constructed inputs, the API nanmean can crash with segment fault. This allows attackers to conduct DoS attacks by construct specific inputs. <br>
**Exploitation**: PoC: [random_shape.py](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/random_shape.py) and [Output](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/crash_info-nanmean.txt).<br>
With 7 inputs: [input1](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input1),  [input2](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input2),  [input3](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input3),  [input4](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input4),  [input5](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input5),  [input6](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input6),  [input7](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input7)

#### [Vulnerability-3]: Segment fault
**Affected version**: version <= 1.3.4 <br>
**Description**: With carefully constructed inputs, the API nanmedian can crash with segment fault. This allows attackers to conduct DoS attacks by construct specific inputs. <br>
**Exploitation**: PoC: [random_shape.py](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/random_shape.py) and [Output](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/crash_info-nanmedian.txt).<br>
With 7 inputs: [input1](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input1),  [input2](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input2),  [input3](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input3),  [input4](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input4),  [input5](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input5),  [input6](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input6),  [input7](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input7)

#### [Vulnerability-4]: Segment fault
**Affected version**: version <= 1.3.4 <br>
**Description**: With carefully constructed inputs, the API nanmin can crash with segment fault. This allows attackers to conduct DoS attacks by construct specific inputs. <br>
**Exploitation**: PoC: [random_shape.py](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/random_shape.py) and [Output](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/crash_info-nanmin.txt).<br>
With 7 inputs: [input1](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input1),  [input2](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input2),  [input3](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input3),  [input4](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input4),  [input5](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input5),  [input6](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input6),  [input7](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input7)

#### [Vulnerability-5]: Segment fault
**Affected version**: version <= 1.3.4 <br>
**Description**: With carefully constructed inputs, the API nanstd can crash with segment fault. This allows attackers to conduct DoS attacks by construct specific inputs. <br>
**Exploitation**: PoC: [random_shape.py](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/random_shape.py) and [Output](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/crash_info-nanstd.txt).<br>
With 7 inputs: [input1](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input1),  [input2](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input2),  [input3](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input3),  [input4](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input4),  [input5](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input5),  [input6](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input6),  [input7](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input7)

#### [Vulnerability-6]: Segment fault
**Affected version**: version <= 1.3.4 <br>
**Description**: With carefully constructed inputs, the API ss can crash with segment fault. This allows attackers to conduct DoS attacks by construct specific inputs. <br>
**Exploitation**: PoC: [random_shape.py](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/random_shape.py) and [Output](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/crash_info-ss.txt).<br>
With 7 inputs: [input1](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input1),  [input2](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input2),  [input3](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input3),  [input4](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input4),  [input5](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input5),  [input6](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input6),  [input7](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input7)

#### [Vulnerability-7]: Segment fault
**Affected version**: version <= 1.3.4 <br>
**Description**: With carefully constructed inputs, the API nanmax can crash with segment fault. This allows attackers to conduct DoS attacks by construct specific inputs. <br>
**Exploitation**: PoC: [random_shape.py](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/random_shape.py) and [Output](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/crash_info-nanmin.txt).<br>
With 7 inputs: [input1](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input1),  [input2](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input2),  [input3](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input3),  [input4](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input4),  [input5](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input5),  [input6](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input6),  [input7](https://github.com/baltsers/polyfuzz/blob/master/bottleneck/input7)

