# Intel PT

## Purpose
Intel pt (Processor Trace) is a hardware processor tracing feature available on
modern intel CPUs. It records the branches that are taken and sometimes their
ip, the state changes and also timing information. There is support for this
hardware in [linux](https://github.com/intel/libipt/blob/master/doc/howto_capture.md)
since version 4.1 with the perf\_event\_open syscall and since version 4.3 in 
the perf tool. Intel pt is also supported in [windows](https://ionescu007.github.io/winipt/) 
since windows 10 version 1803 (Redstone 5 for the full feature set).
