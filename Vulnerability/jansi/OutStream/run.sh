#!/bin/sh

export JANSI_PATH=../jansi-2.4.1-SNAPSHOT.jar

java -cp OutStream.jar:$JANSI_PATH OsJansi.OutStream ./tests/oom-case

