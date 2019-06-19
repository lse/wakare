import sys
import struct

"""
Simple dumper to print binary traces produced by the tracer tool to ascii
"""

def u64(data):
    return struct.unpack("Q", data)[0]

MAGIC = 0xe9cae282c414b97d

def main(path):
    try:
        fd = open(path, "rb")
    except:
        print("Could not open file: {}".format(path))
        return

    header_bytes = fd.read(16)

    if len(header_bytes) != 16:
        print("Unexpected EOF")
        return
    
    magic = u64(header_bytes[0:8])
    edge_count = u64(header_bytes[8:16])

    if magic != MAGIC:
        print("magic number mismatch, got 0x{:x} but expected 0x{:x}".format(magic, MAGIC))
        return

    for i in range(edge_count):
        tuple_bytes = fd.read(16)

        if len(tuple_bytes) != 16:
            print("Unexpected EOF")
            return

        from_addr = u64(tuple_bytes[0:8])
        to_addr = u64(tuple_bytes[8:16])

        print("JMP 0x{:x} -> 0x{:x}".format(from_addr, to_addr))

    map_count_bytes = fd.read(8)

    if len(map_count_bytes) != 8:
        print("Unexpected EOF")
        return

    for i in range(u64(map_count_bytes)):
        tuple_bytes = fd.read(16)

        if len(tuple_bytes) != 16:
            print("Unexpected EOF")
            return

        from_addr = u64(tuple_bytes[0:8])
        to_addr = u64(tuple_bytes[8:16])

        print("MAP 0x{:x} -> 0x{:x}".format(from_addr, to_addr))

    fd.close()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("usage: {} <trace file>".format(sys.argv[0]))
    else:
        main(sys.argv[1])
