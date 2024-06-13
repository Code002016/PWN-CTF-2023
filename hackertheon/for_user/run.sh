#!/bin/bash
docker build -t go_flag .
docker run -d -p 4242:4242 go_flag
