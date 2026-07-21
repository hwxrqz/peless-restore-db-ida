import os
import sys
import zlib
import struct
import pefile


def get_exports_with_absolute_addresses(dll_path, image_base):
    """
    Returns:
        [
            (absolute_address, function_name),
            ...
        ]
    """

    exports = []

    pe = pefile.PE(dll_path)

    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return exports

    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:

        if export.name is None:
            continue

        function_name = export.name.decode("ascii", errors="ignore")

        # export.address already contains RVA
        absolute_address = image_base + export.address

        exports.append(
            (absolute_address, function_name)
        )

    return exports


def ask_image_base(dll_name):

    while True:

        value = input(f"[*] {dll_name} ImageBase: ").strip()

        try:
            return int(value, 16)
        except ValueError:
            print("[!] Invalid ImageBase. Example: 0x7FFF722A0000")


def build_database(entries, output_file):

    #
    # Sort by absolute address for binary search.
    #
    entries.sort(key=lambda x: x[0])

    #
    # Calculate the beginning of the string table.
    #
    current_offset = len(entries) * 16

    string_table = bytearray()
    address_table = []

    #
    # Generate string table.
    #
    for absolute_address, function_name in entries:

        address_table.append(
            (absolute_address, current_offset)
        )

        string_table.extend(
            function_name.encode("ascii")
        )

        string_table.append(0x00)

        current_offset += len(function_name) + 1

    #
    # Build raw database.
    #
    raw_database = bytearray()

    #
    # Write entries.
    #
    for absolute_address, string_offset in address_table:

        raw_database.extend(
            struct.pack("<Q", absolute_address)
        )

        raw_database.extend(
            struct.pack("<Q", string_offset)
        )

    #
    # Write string table.
    #
    raw_database.extend(string_table)

    #
    # Compress database.
    #
    compressed_database = zlib.compress(raw_database)

    with open(output_file, "wb") as f:
        f.write(compressed_database)

    print()
    print(f"[+] Total exports : {len(entries)}")
    print(f"[+] Raw size      : {len(raw_database)} bytes")
    print(f"[+] Packed size   : {len(compressed_database)} bytes")
    print(f"[+] Database saved to '{output_file}'")


def main():

    if len(sys.argv) != 3:
        print()
        print("Usage:")
        print("python generate_import_db.py <dll_directory> <output_file>")
        print()
        sys.exit(1)

    dll_directory = sys.argv[1]
    output_file = sys.argv[2]

    if not os.path.isdir(dll_directory):
        print("[!] DLL directory does not exist.")
        sys.exit(1)

    entries = []

    dll_files = sorted(os.listdir(dll_directory))

    for filename in dll_files:

        if not (
            filename.lower().endswith(".dll")
            or filename.lower().endswith(".exe")
        ):
            continue

        dll_path = os.path.join(
            dll_directory,
            filename
        )

        print()
        image_base = ask_image_base(filename)

        try:

            exports = get_exports_with_absolute_addresses(
                dll_path,
                image_base
            )

            entries.extend(exports)

            print(
                f"[+] Found {len(exports)} exports."
            )

        except Exception as e:

            print(
                f"[!] Failed to parse {filename}: {e}"
            )

    if not entries:

        print("[!] No exports were found.")
        sys.exit(1)

    build_database(entries, output_file)


if __name__ == "__main__":
    main()