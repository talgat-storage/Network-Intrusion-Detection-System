#!/bin/bash

cd ./src
gcc -std=gnu99 -Wall *.c *.h -o my_nids -lpcap
mv my_nids ../bin

