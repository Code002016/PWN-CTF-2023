#!/bin/bash
socat -t -s TCP-LISTEN:${PORT},reuseaddr,fork, EXEC:./${PROB_NAME}

