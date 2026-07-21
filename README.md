# PE-less Restore DB IDA

IDA Pro 9.2 plugin for automatic PE-less import restoration from memory dumps and VAD sections.

The plugin resolves imported API function pointers stored in manually mapped or injected malware samples by matching their absolute addresses against a user-generated binary database.

---

## Description

Many modern malware families do not contain a valid PE Import Address Table (IAT). Instead, they:

* Manually map DLLs.
* Resolve imported APIs dynamically.
* Store imported functions as raw pointers.
* Inject PE-less payloads into RWX VAD regions.
* Use custom loaders or shellcode to bypass standard PE loading mechanisms.

As a result, imported functions are displayed in IDA Pro as anonymous `qword` values.

Before restoration:

```asm
seg000:0000000000021000 dq 7FFF722A14D0h
seg000:0000000000021008 dq 7FFF722A1610h
seg000:0000000000021010 dq 7FFF722A1FA0h
```

After running the plugin:

```asm
seg000:0000000000021000 VirtualProtect     dq 7FFF722A14D0h
seg000:0000000000021008 VirtualFree        dq 7FFF722A1610h
seg000:0000000000021010 GetCurrentProcess  dq 7FFF722A1FA0h
```

This greatly improves both the assembly listing and the Hex-Rays decompiler output.

Before:

```c
LOBYTE(v9) = MEMORY[0x7FFF722A14D0](a1,a2,v8,*a3,v15,&a8) != 0;
```

After:

```c
LOBYTE(v9) = VirtualProtect(a1,a2,v8,*a3,v15,&a8) != 0;
```

---

## Features

* Automatic PE-less import restoration.
* Support for IDA Pro 9.2.
* Binary search over compressed databases.
* User-generated import databases.
* Support for multiple DLL libraries.
* ZLIB-compressed binary storage.
* Resolve imports at the current cursor address.
* Resolve imports for a selected memory range.
* Fast address lookups using absolute virtual addresses.

---

## Typical Workflow

1. Obtain a memory dump of the infected machine.
2. Identify the target process.
3. Dump the injected RWX VAD region.
4. Obtain DLL ImageBases using Volatility.
5. Dump DLLs from the same memory image or copy them from the infected machine.
6. Generate the import database.
7. Load the VAD dump into IDA Pro.
8. Load the plugin.
9. Resolve imported API addresses.

The plugin is intended to be used with DLLs originating from the same memory image or infected system. Therefore, no OS-specific databases are required.

---

# Binary Storage

## Creating an storage

Creating a new database:

```bash
python generate_import_db.py <path_to_dumped_dlls> import_storage.bin
```
Plugin requests storage called `import_storage.bin`

The script will ask for the ImageBase:

```text
[*] kernel32.dll ImageBase: <ImageBase>
```
You may incrementally add as many DLLs as necessary.

The resulting database is stored as:

```text
import_storage.bin
```

No intermediate text files are generated.

The database directly stores:

```text
Function Name <-> Absolute Virtual Address
```

Example:

```text
VirtualProtect      -> 0x7FFF722A14D0
VirtualAlloc        -> 0x7FFF722A11D0
VirtualFree         -> 0x7FFF722A1610
GetCurrentProcess   -> 0x7FFF722A1FA0
htons               -> 0x7FFF71961280
send                -> 0x7FFF71964A30
recv                -> 0x7FFF71964860
```

---

## Binary Storage Format

Each entry is represented as:

```c
struct IMPORT_REC
{
    uint64_t address;
    uint64_t name_offset;
};
```

The database is sorted by absolute virtual addresses.

Function names are stored separately in a string table.

Scheme of binary storage:

<img width="719" height="281" alt="binary_storage" src="https://github.com/user-attachments/assets/95122dfe-fb20-4a89-abed-f764931f5ec6" />

The final database is compressed using ZLIB to reduce its size.

---

## Installing the Plugin

Copy all files from the `plugin` directory into your `IDA plugins` directory

Restart IDA Pro.

The plugin automatically loads the compressed import database during initialization.

---

# Usage

## Resolving a Single Import

Place the cursor on an address containing a function pointer:

```asm
dq 7FFF722A14D0h
```

Run:

```text
Edit -> Plugins -> Resolve PE-less Imports
```

Result:

```asm
VirtualProtect dq 7FFF722A14D0h
```

The plugin automatically renames the current address and creating comment near offset

---

## Resolving Imports for a Selected Range

Select the desired memory range:

```text
0x21000 - 0x21200
```

Run:

```text
Edit -> Plugins -> Resolve PE-less Imports
```

The plugin will iterate over all QWORD values within the selected range and attempt to resolve them.

Example output:

```text
[+] 0x21078 -> RtlInitializeCriticalSection
[+] 0x21080 -> SetFilePointer
[+] 0x21088 -> lstrlen
[+] 0x21090 -> WaitForSingleObject
[+] 0x21098 -> CreateFileA
[+] 0x210A0 -> LoadLibraryA
[+] 0x210A8 -> DeleteFileW
[+] 0x210B0 -> CloseHandle
[+] 0x210B8 -> CreateThread
[+] 0x210C0 -> GetProcAddress
```

---

## Demonstration Video

A short (or not) video demonstrating the entire workflow is available here:

https://github.com/user-attachments/assets/4896b658-9701-48fa-af28-c9316e2e185e

---

## Example Use Case

Suppose an injected malware sample stores imported functions inside an RWX VAD section:

```asm
seg000:00000000000031B9 call cs:qword_21000
```

The referenced QWORD contains:

```asm
qword_21000 dq 7FFF722A14D0h
```

After restoration:

```asm
call cs:VirtualProtect
```

The Hex-Rays decompiler output immediately becomes more readable and significantly simplifies malware analysis.

---

## Tested With

* IDA Pro 9.2
* Windows 10 x64 memory dumps
* Volatility 3
* PE-less malware samples
* Injected VAD sections
* Manually mapped DLL imports

---

## License

MIT License.

---

## Author

Fuzzk6l
