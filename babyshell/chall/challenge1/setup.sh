#!/bin/sh
#

docker build -t "challenge" . --network=host && docker run -d -p "0.0.0.0:2682:2682" --cap-add=SYS_PTRACE challenge