#!bin/bash
make
hostName=$(echo $1 | cut -d : -f1)
env HOSTNAME=${hostName} \
LD_PRELOAD=./CrackOpenSSL.so openssl s_client -connect $1
