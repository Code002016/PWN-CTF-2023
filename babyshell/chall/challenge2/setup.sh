#!/bin/sh
#

docker build -t "challenge" . --network=host && docker run -d -p "0.0.0.0:14014:14014" --cap-add=SYS_PTRACE challenge