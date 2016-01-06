#!/bin/bash

prog_name=$1
start=$2
code_size=$3
entry=$4

file_name=decrypter_${prog_name}.asm
 
cp decrypter.asm ${file_name}    
sed -i "s/###start###/${start}/" ${file_name}
sed -i "s/###size###/${code_size}/" ${file_name}
sed -i "s/###return###/${entry}/" ${file_name}
nasm ${file_name} -f bin -o decrypter_${prog_name}