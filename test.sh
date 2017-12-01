#!/bin/bash
rm test/*
cp tux.ppm pv_keygen pv_encrypt pv_decrypt test/;
cd test;

yes hello | head -n 20 > hello.txt
./pv_keygen key_file; 
./pv_encrypt key_file hello.txt hello.cip;
./pv_decrypt key_file hello.cip hello.pxt; 
diff hello.pxt hello.txt

./pv_keygen key;
./pv_encrypt key tux.ppm tux.cxt ecb; head -n 3 tux.ppm > tux.cxt.ppm; cat tux.cxt  >> tux.cxt.ppm; eog tux.cxt.ppm
./pv_decrypt key tux.cxt tux.pxt.ppm ecb ; eog tux.pxt.ppm

exit 0
