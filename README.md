# PE 病毒实验

PE (Portal Executable) 是 Windows 平台下可执行文件的格式。在本次实验中，我会尝试去修改 PE 文件的程序入口地址，在代码段增加“恶意”代码片段，增加新的 section，以及实现代码在运行时的变形。一般而言，大家完成上述操作会使用 WinHex 之类的工具去手动修改 PE 文件的二进制值，或者是 PE Explorer 之类的软件直接修改相应的值。上述的两种方式，前者像是原始人使用石器，后者像是使用高科技产品而对其原理一无所知。为了保证效率，并且能够深入学习 PE 文件的结构，我选择了编写 Python 脚本去自动化 PE 文件的解析以及部分修改的工作。

下面是我本次实验中使用到的一些工具：

1. Python 
2. MASM32
3. CCF PE Explorer，这个工具可以快捷地查看 PE 的信息，并反汇编二进制代码。只将其作为查看器使用，不使用修改功能。
4. x32dbg，PE 文件动态调试工具。

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

### 入口地址修改

### 在已有节注入代码

### 添加新节

### 指令变形
