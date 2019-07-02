# Tracing experimentation
The goal of this project is to provide a tool able to gather information about
branches taken during a program execution. These branches allow us to build
coverage information about a target program that can then be used for various
purpose such as reverse engineering, devirtualization or binary reconstruction.

## Backends
There are two different backends collecting branch information.

The first backend is based on ptrace. It uses PTRACE\_SINGLEBLOCK in a loop to 
stop on each new basic block target of a branch. It then disassembles the 
instructions of the basic block to find the next branch. This implementation is
naive and has severe limitations. The first one is the speed. Ptrace is 
extremely slow and even for trivial programs the performance is abysmal (/bin/ls -lah
executes in around 10s). Another concern is that it is not easily possible to
filter ip ranges which means that the resulting trace contains not only the program's
execution but also the ip from the libraries.

The second is backend is much more light and fast. It uses Intel Processor Trace
traces to collect the branches. This backend takes as an input a trace collected using
the **perf** tool using the intel pt pmu. The resulting perf.data file contains raw
intel pt traces that can then be processed using libipt to extract all the branches.
The pt perf script in ```scripts``` filters the jumps directly in hardware for smaller
traces.
