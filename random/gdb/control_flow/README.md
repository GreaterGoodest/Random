# Summary

Demonstrates automatically attaching to a running process, setting a breakpoint, and changing a variable to change control flow.

In the provided program (loop_decide.c) a loop continually runs while a variable is set to 0. This variable is only in scope while in main(), so we set a breakpoint in main after attaching and then automatically set the variable to 1. This escapes the infinite loop.

# Usage

set ptrace_scope to 0

```bash
echo 0 > /proc/sys/kernel/yama/ptrace_scope
```

run loop_decide.bin
run attach_debug.sh