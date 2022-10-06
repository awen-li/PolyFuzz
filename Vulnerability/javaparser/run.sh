#!/bin/bash  
  
Root=`pwd`

# compile
javac -cp .:$Root/javaparser.jar jparser.java

# run the case
case=$1
java -cp .:$Root/javaparser.jar jparser $case