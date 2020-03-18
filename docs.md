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

在已有的 section 注入代码意味着，我们不仅需要在某个 section 中添加我们自己编译自汇编、或者手写的二进制代码，还需要让程序能够运行我们添加的代码。要达到这样的目的，需要考虑下面的问题：

1. 添加代码的节必须是可执行的。
2. 程序能够执行到添加的代码。
3. 添加的代码的重定位问题。

首先，为了保证添加的代码可以正常执行，同时为了简便，我们选择直接在 `.text` 段中添加代码。这样做可以避免修改 section header 中的 `Characteristics` 字段，引起杀毒软件的怀疑。其次，为了使得添加的代码能够被正常执行，我选择直接修改程序的 entry point 为添加代码段的开始位置。

下面需要考虑添加什么样的代码，以及代码中地址重定位的问题。首先，我准备添加下面汇编代码所示的代码片段：

```assembly
push 0                             
push hello.403000 # 403000:"System Information"                 
push hello.403000
push 0                             
call dword ptr ds:[<&MessageBoxA>] 
push 0                             
call dword ptr ds:[<&ExitProcess>] 
int3                               
```

这段代码打开一个显示“System Information”的窗口后就结束运行。值得注意的是调用窗口函数的地方，call 指令是对一个地址做操作，取出地址中函数的地址，再跳转到函数地址的地方执行函数。而函数地址保存的地方，恰恰是 `.rdata` 段。通过观察原 `.text` 段的汇编代码，我注意到它打开窗口时，call 指令操作的是一个相对地址，然后在这个相对地址处可以看到一条 jmp 指令。jmp 指令操作对象正是我上面用到的指向 `.rdata` 节的地址。下面是原 `.text` 段的汇编代码：

```assembly
L_00000000:   push 0x0
L_00000002:   push 0x403000
L_00000007:   push 0x403026
L_0000000C:   push 0x0
L_0000000E:   call 0x2e  # 跳到下面的 jmp 指令处
L_00000013:   push 0x0
L_00000015:   push 0x403013
L_0000001A:   push 0x403034
L_0000001F:   push 0x0
L_00000021:   call 0x2e
L_00000026:   push 0x0
L_00000028:   call 0x34
L_0000002D:   int 3 
L_0000002E:   jmp [0x402008] # 0x402008 为 .rdata 里面保存函数入口地址的地址
L_00000034:   jmp [0x402000]
```

注意到本例中的 `.text` 比较短，程序代码大小为 0x3A bytes，节大小为 0x200 bytes。所以从 0x3A 之后，都可以作为添加代码的起点。下面是添加代码的 Python 脚本：

```python
def replace_section(filename: str, section_num: int, start: int, buf: [int]):
    '''buf: 每一项表示一个字节;  
       start: 在 section 中开始替换的位置;         
       section_num: section 在section table 中的位置, 从 0 开始计数
    '''
    with open(filename, "r+b") as f:
        fdno = f.fileno()
        data = mmap.mmap(fdno, 0)
        sno = get_file_header(data)[IDX_NUM_OF_SEC]
        if section_num > sno:        
            raise('Invalid section_num')

        section_hdr = get_section_header(data, section_num)  
        off = section_hdr[IDX_PTR_TO_RAW_DATA]
        raw_sz = section_hdr[IDX_SZ_OF_RAW_DATA]
        if start + len(buf) > raw_sz:
            raise('Too large to write into the section')
		# 开始在节中添加内容
        struct.pack_into("B"*len(buf), data, start+off, *buf)
        # 修改并写回 section header
        section_hdr[IDX_VIR_SZ] = max(start+len(buf), section_hdr[IDX_VIR_SZ])
        set_section_header(data, sno, section_hdr)
```

使用下面命令可以完成代码的添加：

```bash
$./pe.py replace hello.exe 0 0x40  6A 00 68 00 30 40 00 68 00 30 40 00 6A 00 FF 15 08 20 40 00 6A 00 FF 15 00 20 40 00 CC
```

运行上面的脚本添加好代码后，可以使用 PE Explorer 查看是否成功添加在相应添加的位置。之后，为了让代码可以被执行，修改程序入口地址为 `0x1040`。

上述操作都完成后，再次运行代码，其运行结果如下：

![image-20200317195035637](C:\Users\qyang\AppData\Roaming\Typora\typora-user-images\image-20200317195035637.png)

可以看到，打开窗口显示的内容正好是上面添加代码片段想要显示的效果。

### 添加新节

添加一个新节，需要考虑的问题比较多，主要有下面一些：

1. 新节的内容。具体的代码内容。
2. 新节的位置与对齐。文件对齐要根据 optional header 中的 File Alignment 确定，一般值为 `0x100`, 即 512 bytes，刚好是一个磁盘扇区的大小。新加节在文件中的位置要按照文件对齐值对齐。为了尽量不改变已有节，可以将新加节的位置置于所有已有节之后的位置。
3. 新节的 section header 的内容。当添加一个新节的时候我们需要考虑新节代码的大小，即 VirtualSize；新节加载到内存中的位置（VirtualAddress），不能占据之前节的内容；新节在文件中的大小，SizeOfRawData；新节在文件中的偏移位置，PointerToRawData；新节的属性（Characteristics），可写、可读、可执行等。
4. Section header 在文件中的位置。Section table 位于所有 section 之前，因为文件对齐，两者之间可能会存在足够插入一个新的 section header 的空间。但是，如果没有这样大小的空间，就需要将所有 section 向后移 File Alignment 的大小。相应的，所有 section header 中的 PointerToRawData 也需要加上相应的值。
5. 修改 file header 中 NumOfSection 的值。
6. 修改 optional header 中 image size 的值。

下面是添加一个新节的 Python 脚本代码：

```python
def append_section(filename: str, section_file: str):
    '''section_file:
            第一行是 section header
            第二行开始是 section 的内容，用 16 进制数据表示 每个 byte 之间应该有空格
    '''
    with open(filename, "r+b") as f:
        fdno = f.fileno()
        data = mmap.mmap(fdno, 0)
        file_hdr = get_file_header(data)
        sec_no = file_hdr[IDX_NUM_OF_SEC]
        optional_hdr = get_optional_header(data)
        file_alignment = optional_hdr[IDX_FILE_ALIGN]
        # 1）判断是否需要移动 section headers 之后的数据，腾出插入一个 section header 的空间;
        off = get_section_hdr_offset(
            data, sec_no)  # end of section table
        start_of_sections = data.size()  # section 开始的位置
        for i in range(sec_no):
            sec_hdr = get_section_header(data, i)
            start_of_sections = min(
                start_of_sections, sec_hdr[IDX_PTR_TO_RAW_DATA])
        if off + SECTION_HEADER_SZ > start_of_sections:
            print("move sections")
            # 1.1) 把 sections 向后移动
            # section 需要对齐，向后移动 section aligment 的大小
            data.resize(data.size() + file_alignment)
            data.move(start_of_sections, start_of_sections +
                      file_alignment, data.size()-start_of_sections)
            # 1.2）修改 其他section header 的 raw_pointer, 保证它们指向正确的位置 （加上一个 section align 大小的偏移量）
            for i in range(sec_no):
                sec_hdr = get_section_header(data, i)
                sec_hdr[IDX_PTR_TO_RAW_DATA] += file_alignment
        # 2) 插入新的 section header 和 section
        with open(section_file) as f:
            hdr = f.readline().strip().split(' ')
            hdr[1:] = map(lambda x: int(x, 16), hdr[1:])
            hdr[0] = bytes(hdr[0], encoding='utf-8')

            buf = f.readlines()
            buf = [int(byte, 16) for b in buf for byte in b.strip().split()]
            # 2.1）填写新的 section header，raw_size raw_pointer 应该由本函数计算, virtual addr 如果为 0 则填上的 section 大小
            raw_size = (len(buf)+file_alignment -
                        1)//file_alignment*file_alignment
            raw_pointer = (data.size() + file_alignment -
                           1) // file_alignment*file_alignment
            hdr[IDX_PTR_TO_RAW_DATA] = raw_pointer
            hdr[IDX_SZ_OF_RAW_DATA] = raw_size
            if hdr[IDX_VIR_SZ] == 0:
                hdr[IDX_VIR_SZ] = len(buf)
            set_section_header(data, sec_no, hdr)
            # 2.2）在文件结尾加上新的节
            data.resize(raw_size + raw_pointer)
            struct.pack_into(str(len(buf))+'B', data, raw_pointer, *buf)
        # 3）修改 file header 中 num of sec
        file_hdr[IDX_NUM_OF_SEC] += 1
        set_file_header(data, file_hdr)
        # 4) 修改 optional header 中的 size of image
        optional_hdr[IDX_IMG_SZ] += 0x1000
        set_optional_header(data, optional_hdr)
```

新节的内容和其 header 的内容通过一个文本来指定。其中，第一行是 header 的内容，其余内容为新节代码的十六进制的文本。

下面是我准备往 PE 文件中添加的内容，它和原文件中 `.text` 节的内容是一模一样的。为了把注意力集中于如何添加一个新节，这里再添加的新节的内容上简化了。添加完新节之后，为了看到新加代码的执行，还需要把程序入口地址更改到新节加载的位置。

```
.hello 0 4000 200 1000 0 0 0 0 60000020
6A 
00 68 00 30 40 00 68 26 30 40 00 6A 00 E8 1B 00
00 00 6A 00 68 13 30 40 00 68 34 30 40 00 6A 00
E8 08 00 00 00 6A 00 E8 07 00 00 00 CC FF 25 08
20 40 00 FF 25 00 20 40 00 00 00 00 00 00 00 6A
00 68 00 30 40 00 68 00 30 40 00 6A 00 FF 15 08
20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

使用下面的命令可以执行上述修改：

```bash
$./pe.py append hello.exe text.section 
\section header: [b'.hello', 144, 16384, 512, 2560, 0, 0, 0, 0, 1610612768]
$./pe.py ep hello.exe 0x4000
old address of entry point: 0x1040
new address of entry point: 0x4000
```

使用 PE Explorer 查看修改后 PE 文件中的 section table，可以看到有一个新的 `.hello` 的节被成功添加。

![image-20200318213620782](C:\Users\qyang\AppData\Roaming\Typora\typora-user-images\image-20200318213620782.png)

运行可执行文件，可以看到，程序的行为和在做所有修改之前一样，这正是我们的目的。

### 指令变形

在这个任务中，我做了一个非常基础的加密、解密的变形病毒。将编译好的二进制代码通过二进制编辑器手动把部分代码加密，然后另外一部分代码可以做解密工作。这个解密的工作是在程序运行时完成的。

下面是我的变形病毒的汇编代码：

```assembly
...
.code
start:
    call ep
rs:
    ; 编译后 用编辑器对下面一段手动加密
	invoke MessageBox, NULL, offset szText1, offset szCaption1, MB_OK
	invoke MessageBox, NULL, offset szText4, offset szCaption2, MB_OK
	invoke ExitProcess, NULL
ep:
    pop ebx  ; return address 的值，也就是 rs 的地址
    mov ecx, ep-rs ; 加密代码的大小
    mov edi, ebx
decrypt:   ; 解密
    xor byte ptr [edi], 89h
    inc edi
    loop decrypt
    jmp rs  ; 解密完成后执行相应代码
end start
```

`rs` 到 `ep` 之间是我要加密、解密的代码。之后的内容就是解密的内容。

把上面的代码编译后，做成上面一节中添加一个新节时做的文本文件，即下面的内容：

```
.ploy 0 5000 200 1000 0 0 0 0 E0000020
E8 2D 00 00 00 E3 89 E1 89 B9 C9 89 E1 AF B9 C9 
89 E3 89 61 A3 89 89 89 E3 89 E1 9A B9 C9 89 E1 
BD B9 C9 89 E3 89 61 9E 89 89 89 E3 89 61 9F 89 
89 89 5B B9 2D 00 00 00 8B FB 80 37 89 47 E2 FA 
EB C3 FF 25 08 20 40 00 FF 25 00 20 40 00 00 00 
```

需要注意的是，这个新节的 Characteristics 不能完全和 `.text` 节完全一样，它必须还是可写的，因为代码需要变形。

下面通过上面一节的添加新节的方式添加一个新节，然后执行可执行文件，通过动态调试器查看代码的动态变化。

![image-20200318215232696](C:\Users\qyang\AppData\Roaming\Typora\typora-user-images\image-20200318215232696.png)

可以看到原本打开窗口的代码已经完全变成别的没有任何逻辑的代码了。然后执行解密代码，再查看新的代码内容。

![image-20200318215505508](C:\Users\qyang\AppData\Roaming\Typora\typora-user-images\image-20200318215505508.png)

可以看到，打开窗口的汇编代码又恢复了它本来的模样。