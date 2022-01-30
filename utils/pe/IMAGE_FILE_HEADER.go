package pe

import (
	"encoding/binary"
)

// 共占用20B
type IMAGE_FILE_HEADER struct {
	Machine              uint16 // 每个CPU都有唯一的Machine码。兼容32位Intel X86芯片的Machine码为14C。
	NumberOfSections     uint16 // 指出文件中存在的节区数量。该值一定要大于0，且当定义的节区数量与实际节区不同时，将发生运行错误。
	TimeDateStamp        uint32 // 该字段的值不影响文件的运行。只是用来记录编译器创建此文件的时间
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16 // 用来指定IMAGE_OPTIONAL_HEADER32或IMAGE_OPTIONAL_HEADER64结构体的长度
	Characteristics      uint16 // 用于标识文件的属性，文件是否时可运行的形态、是否为dll文件等信息，以bit or的形式组合起来。
}

func parseJIFH(fileheader []byte)(ifh *IMAGE_FILE_HEADER){
	ifh = new(IMAGE_FILE_HEADER)
	ifh.Machine = binary.LittleEndian.Uint16(fileheader[0:])
	ifh.NumberOfSections = binary.LittleEndian.Uint16(fileheader[2:])
	ifh.TimeDateStamp = binary.LittleEndian.Uint32(fileheader[4:])
	ifh.PointerToSymbolTable = binary.LittleEndian.Uint32(fileheader[8:])
	ifh.NumberOfSymbols = binary.LittleEndian.Uint32(fileheader[12:])
	ifh.SizeOfOptionalHeader = binary.LittleEndian.Uint16(fileheader[16:])
	ifh.Characteristics = binary.LittleEndian.Uint16(fileheader[18:])
	return
}

// IMAGE_FILE_HEADER中用到的Machine码
// winnt.h
const (
	IMAGE_FILE_MACHINE_UNKNOWN   = 0x0
	IMAGE_FILE_MACHINE_AM33      = 0x1d3
	IMAGE_FILE_MACHINE_AMD64     = 0x8664
	IMAGE_FILE_MACHINE_ARM       = 0x1c0
	IMAGE_FILE_MACHINE_ARMNT     = 0x1c4
	IMAGE_FILE_MACHINE_ARM64     = 0xaa64
	IMAGE_FILE_MACHINE_EBC       = 0xebc
	IMAGE_FILE_MACHINE_I386      = 0x14c // intel 386
	IMAGE_FILE_MACHINE_IA64      = 0x200 // intel64
	IMAGE_FILE_MACHINE_M32R      = 0x9041
	IMAGE_FILE_MACHINE_MIPS16    = 0x266
	IMAGE_FILE_MACHINE_MIPSFPU   = 0x366
	IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466
	IMAGE_FILE_MACHINE_POWERPC   = 0x1f0
	IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1
	IMAGE_FILE_MACHINE_R4000     = 0x166
	IMAGE_FILE_MACHINE_SH3       = 0x1a2
	IMAGE_FILE_MACHINE_SH3DSP    = 0x1a3
	IMAGE_FILE_MACHINE_SH4       = 0x1a6
	IMAGE_FILE_MACHINE_SH5       = 0x1a8
	IMAGE_FILE_MACHINE_THUMB     = 0x1c2
	IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169
)