#!/bin/sh

OK_TXT="\e[1;32mOK\e[1;0m"
FAIL_TXT="\e[1;31mFAIL\e[1;0m"

SAMPLES=(indirect-calls loop-intensive loop mini-vm multiple singleblock)
MODES=(pie nopie)

# Checking for processor trace support
if ! which perf 1>/dev/null 2>/dev/null;then
    echo "Error: No perf binary detected. Please install perf"
    exit 1
fi

if ! perf list | grep "intel_pt//" 1>/dev/null;then
    echo "Error: No support for intel processor trace"
    exit 1
fi

# Building the samples
echo "Building samples..."
./samples/build.sh

echo "Starting tests"

for folder in "${SAMPLES[@]}"
do
    for mode in "${MODES[@]}"
    do
        rm -f trace.bin
        rm -f trace.out
        rm -f perf.data

        # Collecting trace
        echo "Testing $folder ($mode)"

        PROG_PATH="./samples/$folder/prog.$mode"
        ./scripts/pt_trace.sh $PROG_PATH 2>/dev/null 1>/dev/null

        if [ ! -f ./perf.data ]; then
            echo "Error: Could not generate trace for program '$PROG_PATH'"
            continue
        fi

        # Testing the extractor
        ./extractor -binary $PROG_PATH

        if [ $? -ne 0 ]; then
            echo -e "[$FAIL_TXT] Extractor"
            continue
        fi

        echo -e "[$OK_TXT] Extractor"

        # Testing the converter in text mode
        ./converter -mode text

        if [ $? -ne 0 ]; then
            echo -e "[$FAIL_TXT] Converter (txt)"
            continue
        fi

        echo -e "[$OK_TXT] Converter (txt)"
        mv trace.out "./samples/$folder/trace_$mode.txt"

        # Testing the converter in sqlite mode
        ./converter -mode sqlite

        if [ $? -ne 0 ]; then
            echo -e "[$FAIL_TXT] Converter (sqlite)"
            continue
        fi

        echo -e "[$OK_TXT] Converter (sqlite)"

        mv trace.out "./samples/$folder/trace_$mode.db"
        mv trace.bin "./samples/$folder/trace_$mode.bin"
    done
done
