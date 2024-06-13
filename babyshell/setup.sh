#!/bin/sh
#

sudo docker build -t "babyshellcode" . --network=host && sudo docker run -d -p "0.0.0.0:2222:9999" --cap-add=SYS_PTRACE babyshellcode