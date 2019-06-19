# Trace format

The trace format aims to be barebones and only contains information about
edges and program mappings.

## Specification
### Version 1.0

| size | Description |
| ---- | ----------- |
|  8   | Magic (0xe9cae282c414b97d) |
|  8   | Edge count  |
|  edge count * sizeof(trace\_entry) | Edge entries |
|  8   | Program mapping count |
| mapping count * sizeof(mapping\_entry) | Memory mapping entries |

The mapping part only contains the executable pages of the target program.

Trace entry format:

| size | Description  |
| ---- | ------------ |
|  8   | Address from |
|  8   | Address to   |

Mapping entry format:

| size | Description   |
| ---- | -----------   |
|  8   | Address start |
|  8   | Address end   |
