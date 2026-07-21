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

    wanted_name = "Resolve PE-less imports"

    wanted_hotkey = ""


    def init(self):

        print("[+] PE-less Imports plugin loaded")

        db_path = (
            ida_diskio.idadir(
                ida_diskio.PLG_SUBDIR
            )
            + "/import_storage.bin"
        )

        import_search.LoadImports(db_path)

        print("[+] Import database loaded")

        return ida_idaapi.PLUGIN_KEEP


    def run(self, arg):

        #
        # Current address.
        #
        ea = ida_kernwin.get_screen_ea()

        #
        # Read qword.
        #
        value = ida_bytes.get_qword(ea)

        #
        # Search.
        #
        name = import_search.FindImport(value)

        if not name:

            print(
                f"[-] Import not found "
                f"for 0x{value:X}"
            )

            return


        #
        # Rename.
        #
        ida_name.set_name(
            ea,
            name,
            ida_name.SN_FORCE
        )

        #
        # Add comment.
        #
        ida_bytes.set_cmt(
            ea,
            name,
            False
        )

        print(
            f"[+] Found import:"
            f" {name} "
            f"(0x{value:X})"
        )


    def term(self):

        pass


def PLUGIN_ENTRY():

    return peless_imports_plugin_t()