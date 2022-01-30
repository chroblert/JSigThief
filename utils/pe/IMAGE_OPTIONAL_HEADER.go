package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func parseJIOH(optionheader []byte) (interface{}, error, int, bool) {
	var (
		sz = uint16(len(optionheader))
		ohMagic uint16
		ohMagicSz = binary.Size(ohMagic)
	)
	if sz < uint16(ohMagicSz){
		return nil, fmt.Errorf("optional header size is less than optional header magic size"), 0, false
	}
	//ohMagic = binary.LittleEndian.Uint16(optionheader)
	r := bytes.NewReader(optionheader)
	var err error
	read := func(data interface{}) bool {
		err = binary.Read(r, binary.LittleEndian, data)
		return err == nil
	}
	if !read(&ohMagic){
		return nil, fmt.Errorf("failure to read optional header magic:%v", err), 0, false
	}
	switch ohMagic {
	case 0x10b: // PE32
		var (
			oh32 IMAGE_OPTIONAL_HEADER32
			oh32MinSz = binary.Size(oh32) -binary.Size(oh32.DataDirectory) // 可选头中减去目录项所占据的大小
		)
		if sz < uint16(oh32MinSz) {
			return nil, fmt.Errorf("optional header size(%d) is less minimum size (%d) of PE32 optional header", sz, oh32MinSz), 0, false
		}
		// init oh32 fields
		oh32.Magic = ohMagic
		if !read(&oh32.MajorLinkerVersion) ||
			!read(&oh32.MinorLinkerVersion) ||
			!read(&oh32.SizeOfCode) ||
			!read(&oh32.SizeOfInitializedData) ||
			!read(&oh32.SizeOfUninitializedData) ||
			!read(&oh32.AddressOfEntryPoint) ||
			!read(&oh32.BaseOfCode) ||
			!read(&oh32.BaseOfData) ||
			!read(&oh32.ImageBase) ||
			!read(&oh32.SectionAlignment) ||
			!read(&oh32.FileAlignment) ||
			!read(&oh32.MajorOperatingSystemVersion) ||
			!read(&oh32.MinorOperatingSystemVersion) ||
			!read(&oh32.MajorImageVersion) ||
			!read(&oh32.MinorImageVersion) ||
			!read(&oh32.MajorSubsystemVersion) ||
			!read(&oh32.MinorSubsystemVersion) ||
			!read(&oh32.Win32VersionValue) ||
			!read(&oh32.SizeOfImage) ||
			!read(&oh32.SizeOfHeaders) ||
			!read(&oh32.CheckSum) ||
			!read(&oh32.Subsystem) ||
			!read(&oh32.DllCharacteristics) ||
			!read(&oh32.SizeOfStackReserve) ||
			!read(&oh32.SizeOfStackCommit) ||
			!read(&oh32.SizeOfHeapReserve) ||
			!read(&oh32.SizeOfHeapCommit) ||
			!read(&oh32.LoaderFlags) ||
			!read(&oh32.NumberOfRvaAndSizes) {
			return nil, fmt.Errorf("failure to read PE32 optional header: %v", err), 0, true
		}
		dd, err := readDataDirectories(r, sz-uint16(oh32MinSz), oh32.NumberOfRvaAndSizes)
		if err != nil {
			return nil, err, 0, true
		}
		copy(oh32.DataDirectory[:], dd)
		return &oh32, nil, oh32MinSz, true
	case 0x20b: // PE64
		var(
			oh64 IMAGE_OPTIONAL_HEADER64
			oh64MinSz = binary.Size(oh64) - binary.Size(oh64.DataDirectory)
		)
		if sz < uint16(oh64MinSz){
			return nil, fmt.Errorf("optional header size(%d) is less minimum size (%d) for PE32+ optional header", sz, oh64MinSz), 0, false
		}
		oh64.Magic = ohMagic
		if !read(&oh64.MajorLinkerVersion) ||
			!read(&oh64.MinorLinkerVersion) ||
			!read(&oh64.SizeOfCode) ||
			!read(&oh64.SizeOfInitializedData) ||
			!read(&oh64.SizeOfUninitializedData) ||
			!read(&oh64.AddressOfEntryPoint) ||
			!read(&oh64.BaseOfCode) ||
			!read(&oh64.ImageBase) ||
			!read(&oh64.SectionAlignment) ||
			!read(&oh64.FileAlignment) ||
			!read(&oh64.MajorOperatingSystemVersion) ||
			!read(&oh64.MinorOperatingSystemVersion) ||
			!read(&oh64.MajorImageVersion) ||
			!read(&oh64.MinorImageVersion) ||
			!read(&oh64.MajorSubsystemVersion) ||
			!read(&oh64.MinorSubsystemVersion) ||
			!read(&oh64.Win32VersionValue) ||
			!read(&oh64.SizeOfImage) ||
			!read(&oh64.SizeOfHeaders) ||
			!read(&oh64.CheckSum) ||
			!read(&oh64.Subsystem) ||
			!read(&oh64.DllCharacteristics) ||
			!read(&oh64.SizeOfStackReserve) ||
			!read(&oh64.SizeOfStackCommit) ||
			!read(&oh64.SizeOfHeapReserve) ||
			!read(&oh64.SizeOfHeapCommit) ||
			!read(&oh64.LoaderFlags) ||
			!read(&oh64.NumberOfRvaAndSizes) {
			return nil, fmt.Errorf("failure to read PE32+ optional header: %v", err), 0, false
		}

		dd, err := readDataDirectories(r, sz-uint16(oh64MinSz), oh64.NumberOfRvaAndSizes)
		if err != nil {
			return nil, err, 0, false
		}
		copy(oh64.DataDirectory[:], dd)
		return &oh64, nil, oh64MinSz, false
	default:
		return nil, fmt.Errorf("optional header has unexpected Magic of 0x%x", ohMagic), 0, false
	}
}
