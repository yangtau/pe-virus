#!/usr/bin/env python3
import pefile
import sys
import mmap
import struct
from functools import lru_cache

E_LFANEW_OFFSET = 0x3c

# file header
FILE_HEADER_SIZE = 0x14
FILE_HEADER_FMT = '2H3I2H'  # H: word I: dword B:byte
IDX_NUM_OF_SEC = 1
IDX_SZ_OF_OP_HDR = 5

# optional header
OPTIONAL_HEADER_FMT = 'H2B9I5H4I2H6I'
IDX_ENTRY_POINT = 6
IDX_IMG_SZ = 18
IDX_SEC_ALIGN = 10
IDX_FILE_ALIGN = 11

# sction header
SECTION_HEADER_FMT = '8s6I2HI'
SECTION_HEADER_SZ = 0x28
IDX_SZ_OF_RAW_DATA = 3
IDX_PTR_TO_RAW_DATA = 4
IDX_VIR_SZ = 1


@lru_cache(maxsize=1)
def get_e_lfanew(data) -> int:
    # 0x3c: the offset of e_lfanew
    return struct.unpack_from("I", data, 0x3c)[0]


@lru_cache(maxsize=1)
def get_file_header(data) -> list:
    off = get_e_lfanew(data) + 4
    return list(struct.unpack_from(FILE_HEADER_FMT, data, off))


def set_file_header(data, hdr: list):
    off = get_e_lfanew(data) + 4
    struct.pack_into(FILE_HEADER_FMT, data, off, *hdr)


@lru_cache(maxsize=1)
def get_optional_header(data) -> list:
    # 4 是 nt header Signature 的大小
    off = get_e_lfanew(data) + 4 + FILE_HEADER_SIZE
    optional_header = list(struct.unpack_from(
        OPTIONAL_HEADER_FMT, data, off))
    return optional_header


def set_optional_header(data, optional_header: list):
    e_lfanew = struct.unpack_from("I", data, 0x3c)[0]
    off = e_lfanew+4+FILE_HEADER_SIZE
    struct.pack_into(OPTIONAL_HEADER_FMT, data, off, *optional_header)


@lru_cache(maxsize=1)
def get_section_hdr_offset(data, num: int):
    file_header = get_file_header(data)
    return get_e_lfanew(data) + 4 + FILE_HEADER_SIZE + \
        file_header[IDX_SZ_OF_OP_HDR] + num * SECTION_HEADER_SZ


@lru_cache(maxsize=4)
def get_section_header(data, num: int) -> list:
    off = get_section_hdr_offset(data, num)
    return list(struct.unpack_from(SECTION_HEADER_FMT, data, off))


def set_section_header(data, num: int, hdr):
    off = get_section_hdr_offset(data, num)
    struct.pack_into(SECTION_HEADER_FMT, data, off, *hdr)


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

        struct.pack_into("B"*len(buf), data, start+off, *buf)
        # 修改 virtual size, 不修改似乎也能成功加载，不知道是不是因为操作系统以页为单位映射加载(mmap)，而实验中的 section 都是小于一个页的大小
        section_hdr[IDX_VIR_SZ] = max(start+len(buf), section_hdr[IDX_VIR_SZ])
        set_section_header(data, sno, section_hdr)


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

            print('section header:', hdr)
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


def show_pe(filename, part=''):
    pe = pefile.PE(filename)
    if part == '':
        print(pe)
    elif part == 'dos_header':
        print(pe.DOS_HEADER)
    elif part == 'file_header':
        print(pe.FILE_HEADER)
    elif part == 'optional_header':
        print(pe.OPTIONAL_HEADER)
    else:
        for s in pe.sections:
            if str(s.Name, encoding='utf-8').startswith(part):
                print(s)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:%s [option] [filename] ..." % (sys.argv[0]))
        exit()
    if sys.argv[1] == 'show':
        if len(sys.argv) == 3:
            show_pe(sys.argv[2])
        else:
            for part in sys.argv[3:]:
                show_pe(sys.argv[2], part=part)
    elif sys.argv[1] == 'ep':
        if len(sys.argv) < 4:
            print("Usage:%s ep [filename] [new entry point]" % (sys.argv[0]))
            exit()
        change_entry_point(sys.argv[2], int(sys.argv[3], 0))
    elif sys.argv[1] == 'replace':
        if len(sys.argv) < 6:
            print(
                "Usage:%s replace [filename] [section number] [offset] [bytes]")
            print("bytes: 37 ef 0a ... ff")
            exit()
        buf = list(map(lambda x: int(x, 16), sys.argv[5:]))
        print(buf)
        replace_section(sys.argv[2], int(
            sys.argv[3], 0), int(sys.argv[4], 0), buf)
    elif sys.argv[1] == 'append':
        if len(sys.argv) != 4:
            print("Usage: %s append [filename] [section_file]" % sys.argv[0])
            exit()
        append_section(sys.argv[2], sys.argv[3])
    else:
        print("Unknown option!")
