# (c) 2026, Fuzzk6l

from ctypes import *
import zlib
import bisect

tokens = None
decomp = None


class ImportRecBin(Structure):
    _fields_ = [
        ("address", c_uint64),
        ("off", c_uint64)
    ]

    def __lt__(self, other):
        return self.address < other


def LoadImports(file_name):
    global tokens
    global decomp

    with open(file_name, "rb") as f:

        compressed = bytes(f.read())

        decomp = zlib.decompress(compressed)

        #
        # Every record is 16 bytes.
        #
        num_items = len(decomp) // 16

        tokens_arr = ImportRecBin * num_items

        tokens = tokens_arr.from_buffer_copy(decomp)


def FindImport(address):

    i = bisect.bisect_left(tokens, address)

    if i >= len(tokens):
        return None

    if tokens[i].address != address:
        return None

    name = ""

    for c in decomp[tokens[i].off:]:

        if c == 0:
            break

        name += chr(c)

    return name