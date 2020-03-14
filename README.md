# PE 病毒实验

PE (Portal Executable) 是 Windows 平台下可执行文件的格式。在本次实验中，我会尝试去修改 PE 文件的程序入口地址，在代码段增加“恶意”代码片段，增加新的 section，以及实现代码在运行时的变形。一般而言，大家完成上述操作会使用 WinHex 之类的工具去手动修改 PE 文件的二进制值，或者是 PE Explorer 之类的软件直接修改相应的值。上述的两种方式，前者像是原始人使用石器，后者像是使用高科技产品而对其原理一无所知。为了保证效率，并且能够深入学习 PE 文件的结构，我选择了编写 Python 脚本去自动化 PE 文件的解析以及部分修改的工作。

下面是我本次实验中使用到的一些工具：

1. Python 
2. pefile，一个 PE 文件解析的 Python 库。只使用其查看信息的功能，不使用别的功能。
3. MASM32
4. CCF PE Explorer，这个工具可以快捷地查看 PE 的信息，并反汇编二进制代码。只将其作为查看器使用，不使用修改功能。
5. x32dbg，PE 文件动态调试工具。

下面，我会先简单介绍 PE 可执行文件的格式，然后展示实验内容。

## PE 可执行文件格式简介

PE 文件起源于 DOS 的可执行文件，所以现在的 PE 文件还是以一个 DOS header 作为开头。DOS header 中最有用的是 `e_lfanew` 字段，它是 NT header 在文件中的偏移量。NT header 的结构如下：

```c
struct _IMAGE_NT_HEADERS {
0x00 DWORD Signature;
0x04 _IMAGE_FILE_HEADER FileHeader;
0x18 _IMAGE_OPTIONAL_HEADER OptionalHeader;
};
```

NT header 中的 `FileHeader`, `OptionalHeader` 结构分别如下所示：

```c
struct _IMAGE_FILE_HEADER {
0x00 WORD Machine;
0x02 WORD NumberOfSections; // Sections 数目，可计算出 section table 的大小
0x04 DWORD TimeDateStamp;
0x08 DWORD PointerToSymbolTable;
0x0c DWORD NumberOfSymbols;
0x10 WORD SizeOfOptionalHeader; // optional header 的大小
0x12 WORD Characteristics;
};
```

```c
struct _IMAGE_OPTIONAL_HEADER {
0x00 WORD Magic;
0x02 BYTE MajorLinkerVersion;
0x03 BYTE MinorLinkerVersion;
0x04 DWORD SizeOfCode;
0x08 DWORD SizeOfInitializedData;
0x0c DWORD SizeOfUninitializedData;
0x10 DWORD AddressOfEntryPoint;
0x14 DWORD BaseOfCode;
0x18 DWORD BaseOfData;
0x1c DWORD ImageBase; //The preferred address of the first byte of image when loaded into memory;
0x20 DWORD SectionAlignment; // The alignment (in bytes) of sections when they are loaded into memory.
0x24 DWORD FileAlignment; // The alignment factor (in bytes) that is used to align the raw data of sections in the image file. 
0x28 WORD MajorOperatingSystemVersion;
0x2a WORD MinorOperatingSystemVersion;
0x2c WORD MajorImageVersion;
0x2e WORD MinorImageVersion;
0x30 WORD MajorSubsystemVersion;
0x32 WORD MinorSubsystemVersion;
0x34 DWORD Win32VersionValue;
0x38 DWORD SizeOfImage; // The size (in bytes) of the image, including all headers, as the image is loaded in memory.
0x3c DWORD SizeOfHeaders;
0x40 DWORD CheckSum;
0x44 WORD Subsystem;
0x46 WORD DllCharacteristics;
0x48 DWORD SizeOfStackReserve;
0x4c DWORD SizeOfStackCommit;
0x50 DWORD SizeOfHeapReserve;
0x54 DWORD SizeOfHeapCommit;
0x58 DWORD LoaderFlags;
0x5c DWORD NumberOfRvaAndSizes;
0x60 _IMAGE_DATA_DIRECTORY DataDirectory[16];
};
```

File header 和 Optional header 中一些重要的，实验中可能会用到的项已经在上面的代码中给出了注释。

紧跟着这些 headers 之后的是 section table，它保存了 各个 section header。Section header 的结构如下：

```c
typedef struct _IMAGE_SECTION_HEADER {
0x00 BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
union {
0x08 DWORD PhysicalAddress;
0x08 DWORD VirtualSize; // section 加载到内存中的大小，如果大于 SizeOfRawData, 内存中多余空间应置为 0
} Misc;
0x0c DWORD VirtualAddress; // 虚拟内存中加载位置
0x10 DWORD SizeOfRawData; // section 在文件中的大小
0x14 DWORD PointerToRawData; // section 在文件中的位置
0x18 DWORD PointerToRelocations;
0x1c DWORD PointerToLinenumbers;
0x20 WORD NumberOfRelocations;
0x22 WORD NumberOfLinenumbers;
0x24 DWORD Characteristics; // section 的一些属性，Writable，Readable，Executable...
};
```

Section header 是本次实验中涉及，比较多的地方，需要对其修改，或者填充等操作。

PE 文件之后的内容就是各个 section 的二进制文件的内容。

需要指出的是，上面介绍的格式并不是全部 PE 文件的通用格式，而是本次实验中使用到的 `.exe` 文件的具体格式。

## 实验内容

这次实验的具体对象是一个弹出两个窗口的小程序，其 masm32 汇编代码如下：

```asm
.386
.model flat, stdcall
option casemap:none

include /masm32/include/windows.inc
include /masm32/include/user32.inc
include /masm32/include/kernel32.inc
includelib /masm32/lib/user32.lib
includelib /masm32/lib/kernel32.lib

.data
szCaption1 db "System Information", 0
szCaption2 db "System Information", 0
szText1    db "Hello, World!", 0
szText2    db "Destroy!", 0
.code
start:
	invoke MessageBox, NULL, offset szText1, offset szCaption1, MB_OK
	invoke MessageBox, NULL, offset szText2, offset szCaption2, MB_OK
	invoke ExitProcess, NULL
end start
```

使用 masm32 编译上面的代码片段，然后 link，就得到了一个 `.exe` 的可执行文件。运行这个程序，会在弹出两个窗口之后就结束运行。

我们可以使用 `python3 pe.py show hello.exe [option]` 查看一下该 PE 文件的信息。

使用命令 `python3 pe.py show hello.exe optional_header` 查看 Optional Header 的信息，可以看到程序的入口地址是 `0x1000`，虚拟内存的加载基地址是 `0x400000`，还有一些其他的信息。

```
[IMAGE_OPTIONAL_HEADER]
...
0xD8       0x10  AddressOfEntryPoint:           0x1000
0xDC       0x14  BaseOfCode:                    0x1000
0xE0       0x18  BaseOfData:                    0x2000
0xE4       0x1C  ImageBase:                     0x400000
0xE8       0x20  SectionAlignment:              0x1000
0xEC       0x24  FileAlignment:                 0x200
...
0x100      0x38  SizeOfImage:                   0x4000
0x104      0x3C  SizeOfHeaders:                 0x400
...
```

使用 `python3 pe.py show hello.exe .text` 查看 `.text` 段的 section header 的内容：

```
[IMAGE_SECTION_HEADER]
0x1A8      0x0   Name:                          .text
0x1B0      0x8   Misc:                          0x3A
0x1B0      0x8   Misc_PhysicalAddress:          0x3A
0x1B0      0x8   Misc_VirtualSize:              0x3A
0x1B4      0xC   VirtualAddress:                0x1000
0x1B8      0x10  SizeOfRawData:                 0x200
0x1BC      0x14  PointerToRawData:              0x400
0x1C0      0x18  PointerToRelocations:          0x0
0x1C4      0x1C  PointerToLinenumbers:          0x0
0x1C8      0x20  NumberOfRelocations:           0x0
0x1CA      0x22  NumberOfLinenumbers:           0x0
0x1CC      0x24  Characteristics:               0x60000020
```

下面我会依次阐述我所做的四个关于 PE 文件的病毒实验，分别为修改程序入口地址、在已有的 section 中注入代码、添加一个新的 section、实现新的 section 中代码的运行时变形。

### 入口地址修改

入口地址的修改比较简单，直接在 optional header 中修改相应位置的值即可。比修改更为重要的问题是找到想要修改的入口地址的位置。这里，我们需要使用将二进制代码 disassemble 到汇编代码，以便于选取合适的位置。其实对于 x86 这样的不需要代码对齐的复杂指令集，还可以将自己想要执行的指令编译成二进制代码，然后在文件中查找是否有相应的二进制片段。下面我使用 PE Explorer 查看 `.text` 节的汇编代码：

```assembly
L_00000000:   push 0x0
L_00000002:   push 0x403000
L_00000007:   push 0x403026
L_0000000C:   push 0x0
L_0000000E:   call 0x2e
L_00000013:   push 0x0          <= 第一个窗口函数调用结束的位置
L_00000015:   push 0x403013
L_0000001A:   push 0x403034
L_0000001F:   push 0x0
L_00000021:   call 0x2e
L_00000026:   push 0x0
L_00000028:   call 0x34
L_0000002D:   int 3 
L_0000002E:   jmp [0x402008]
L_00000034:   jmp [0x402000]
```

可以看到，这段汇编代码的功能就是调用了三个函数。我们可以大胆的推测前两个函数正好对应着前两个窗口。我们现在把入口地址修改到打开第二个窗口的地方，也就是相对偏移为 `0x13`的位置。注意到 `.text` 节加载到虚拟内存的相对地址为 `0x1000`, 所以我们可以将入口地址修改到 `0x1013`。

下面使用 `python3 pe.py ep hello.exe 0x1013`，输出:

```
old address of entry point: 0x1000
new address of entry point: 0x1013
```

修改工作可能成功了，再次运行 `hello.exe` 文件，可以看到，第一个显示 “Hello World!”的窗口已经被跳过了。

下面是修改入口地址的 Python 脚本的节选：

```python
def change_entry_point(filename: str, new_entry_point: int):
    with open(filename, "r+b") as f:
        fdno = f.fileno()
        data = mmap.mmap(fdno, 0)
        optional_header = get_optional_header(data)
        print("old address of entry point: %s" %
              (hex(optional_header[IDX_ENTRY_POINT])))
        optional_header[IDX_ENTRY_POINT] = new_entry_point
        set_optional_header(data, optional_header)
        print("new address of entry point: %s" % (hex(new_entry_point)))
```

这段代码的逻辑比较简单，首先获取 optional header，然后修改 entry point，最后将 optional header 写回即可。

### 在已有节注入代码

### 添加新节

### 指令变形
