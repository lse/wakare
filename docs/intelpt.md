# Intel PT

## Description
Intel pt (Processor Trace) is a hardware processor tracing feature available on
modern intel CPUs starting with the broadwell [architecture](https://github.com/torvalds/linux/blob/master/tools/perf/Documentation/intel-pt.txt#L13).
There is support for thischardware in [linux](https://github.com/intel/libipt/blob/master/doc/howto_capture.md)
since version 4.1 with the perf\_event\_open syscall and since version 4.3 in 
the perf tool. Intel pt is also supported in [windows](https://ionescu007.github.io/winipt/) 
since windows 10 version 1803 (Redstone 5 for the full feature set).

This hardware PMU can record code execution accross all CPU cores. It does this by
recording information about branches (conditional jumps, indirect jumps...) and
also tracking state changes (32bit/64bit switch, SGX, VMX...). The benefit of using
this hardware backed method is mainly the speed. It does not modifiy the code (as
dynamic recompilation frameworks do) and it doesn't rely on heavy apis such as ptrace.
It can also trace code in both user and kernel mode.

## How to capture traces ?
Traces can be captured in multiple ways. We can use the raw api by making a kernel module,
use the perf\_event\_open syscall or use the perf tool.
