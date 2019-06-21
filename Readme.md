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
naive and has severe limitations. The first one is the speed. ptrace is 
extremely slow and even for trivial programs the performance is abysmal 
("/bin/ls" runs in around 4s while "/bin/ls -lah" runs in 76s). Another concern
is that it is impossible to filter on an IP range.
