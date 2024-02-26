#!/bin/bash

pid=$(pgrep loop_decide.bin)
echo "PID: $pid"

gdb -p $pid --command=gdb_script.gdb