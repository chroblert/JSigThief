package pe

type IMAGE_OPTIONAL_HEADER32 struct {
	Magic                       uint16 //* 32位为 010B，64位为 020B
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32 //* 保存EP(入口点)的RVA(相对虚拟地址).指出程序最先执行的代码起始地址，相当重要。
	BaseOfCode                  uint32
	BaseOfData                  uint32
	ImageBase                   uint32 //* 32位系统中进程虚拟内存的范围是0-FFFFFFFF.PE文件被装载到如此大的内存中时，ImageBase指出文件的优先装入地址。装入后，设置EIP=ImageBase+AddressOfEntryPoint
	SectionAlignment            uint32 //* 指定节区在内存中的最小单位
	FileAlignment               uint32 //* 指定节区在文件中的最小单位
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32 //* 指定PE Image在虚拟内存中所占空间的大小。
	SizeOfHeaders               uint32 //* 用来指出整个PE头的大小。该值必须是FileAlignment的整数倍。第一节区所在位置与SizeOfHeaders距文件开始偏移的量相同。
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32 //* 用来指定DataDirectory数组的个数
	DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}
