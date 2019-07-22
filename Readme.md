# Tracing experimentation
The goal of this project is to provide a set of tools able to produce an execution
trace for a given program. The resulting trace can then be used to gather information
about code coverage, recover indirect branches targets or even help binary devirtualization.

## Collecting traces
Only Intel PT traces collected by perf are supported by the tool. To collect a trace with
perf you can specify the intel pt pmu as such:

```
$ perf record -e intel_pt//u prog <args...>
```

You can also use the provided scripts that adds a few optimizations to minimize trace drops
(needs root):

```
# ./scripts/pt_trace.sh
```

## Trace content
Traces produced by the tool contain the following pieces of information:
- Branches:
    - Type (Jump/Cond Jump/Call)
    - Source address
    - Destination address
- Executable mappings:
    - Address range
    - File path
- Basic block hitcount:
    - Address
    - Hitcount

## Project structure
The project is divided into two different programs. The first one is called "extractor".
It takes as an input an execution trace in a foreign format and converts it to a 
more generic representation in the form of a protobuf message stream. The second program
is the "converter", it uses the protobuf messages and converts them to a form more suitable
for other programs to use.

```
                                                                         _ text
                  +-----------+                         +-----------+   /
input trace ----> | extractor | --> protobuf stream --> | converter | --
                  +-----------+                         +-----------+   \_ sqlite
```

- Supported input formats:
    - perf data file containing Intel PT data

- Supported output:
    - text
    - sqlite

## Limitations
For now the project has a few limitations:
- Only supports x86\_64
- No support for programs using multiple cores/threads

## Dependencies
- protobuf
- libipt
- sqlite3
- cmake
