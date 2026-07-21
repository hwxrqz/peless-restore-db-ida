#!/usr/bin/python3

import ida_idaapi
import ida_bytes
import ida_name
import ida_kernwin
import ida_diskio

import import_search


class peless_imports_plugin_t(ida_idaapi.plugin_t):

    flags = 0

    comment = "Resolve PE-less imports"
    help = ""

    wanted_name = "Resolve PE-less Imports"
    wanted_hotkey = ""


    def init(self):

        print("PE-less Imports plugin by Fuzzk6l (c) 2026")

        db_path = (
            ida_diskio.idadir(
                ida_diskio.PLG_SUBDIR
            )
            + "/import_storage.bin"
        )

        import_search.LoadImports(db_path)

        print("[+] Import database loaded")

        return ida_idaapi.PLUGIN_KEEP


    def ResolveAddress(self, ea):

        value = ida_bytes.get_qword(ea)

        if value == 0:
            return False

        name = import_search.FindImport(value)

        if not name:
            return False

        #
        # Delete previous data representation.
        #

        ida_bytes.del_items(ea)

        #
        # Create qword.
        #

        ida_bytes.create_qword(ea, 8)

        #
        # Rename import.
        #

        ida_name.set_name(
            ea,
            name,
            ida_name.SN_FORCE
        )

        #
        # Set comment.
        #

        ida_bytes.set_cmt(
            ea,
            name,
            False
        )

        print(
            f"[+] 0x{ea:X} -> {name}"
        )

        return True


    def ResolveCurrentEA(self):

        ea = ida_kernwin.get_screen_ea()

        if not self.ResolveAddress(ea):

            value = ida_bytes.get_qword(ea)

            print(
                f"[-] Import not found for "
                f"0x{value:X}"
            )


    def ResolveSelection(self, start_ea, end_ea):

        print()
        print(
            f"[+] Resolving imports "
            f"from 0x{start_ea:X} "
            f"to 0x{end_ea:X}"
        )
        print()

        count = 0

        ea = start_ea

        while ea < end_ea:

            if self.ResolveAddress(ea):
                count += 1

            ea += 8

        print()
        print(
            f"[+] Successfully resolved "
            f"{count} imports."
        )


    def run(self, arg):

        #
        # Check whether a range is selected.
        #

        result = ida_kernwin.read_range_selection(None)

        #
        # Resolve selected memory region.
        #

        if result[0]:

            start_ea = result[1]
            end_ea = result[2]

            self.ResolveSelection(
                start_ea,
                end_ea
            )

            return

        #
        # Resolve current qword.
        #

        self.ResolveCurrentEA()


    def term(self):

        pass


def PLUGIN_ENTRY():

    return peless_imports_plugin_t()