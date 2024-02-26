# Summary

# Usage

set ptrace_scope to 0

```bash
echo 0 > /proc/sys/kernel/yama/ptrace_scope
```

run loop_decide.bin
run attach_debug.sh