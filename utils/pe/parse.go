package pe

import (
	"encoding/binary"
	"fmt"
	"github.com/chroblert/jgoutils/jlog"
	"os"
)

type PEFILE struct{
	DosHeader      *J_IMAGE_DOS_HEADER
	FileHeader     *IMAGE_FILE_HEADER
	OptionalHeader interface{}
	DataDirectoryBase int64
	Is32 	bool //OptionalHeader32 or OptionalHeader64

}

func Parse(peName string) (pefile *PEFILE,err error){
	pefile = new(PEFILE)
	f,err := os.Open(peName)
	if err != nil{
		jlog.Error(err)
		return
	}
	var dosheader [64]byte
	_,err = f.ReadAt(dosheader[0:],0)
	if err != nil{
		jlog.Error(err)
		return
	}
	// 判断是否是PE文件
	if !(dosheader[0] == 'M' && dosheader[1] == 'Z'){
		return nil,fmt.Errorf("[!]请输入一个PE文件")
	}
	pefile.DosHeader = parseIDH(dosheader[0:])
	// nt头中的签名
	var signature [4]byte
	f.ReadAt(signature[0:],int64(pefile.DosHeader.E_lfanew))
	if !(signature[0] == 'P' && signature[1] == 'E'){
		return nil,fmt.Errorf("[!]请输入一个PE文件")
	}
	// IMAGE_FILE_HEADER
	var fileheader [0x20]byte
	_,err = f.ReadAt(fileheader[:],int64(pefile.DosHeader.E_lfanew)+4)
	if err != nil{
		jlog.Error(err)
		return nil,err
	}
	pefile.FileHeader = parseJIFH(fileheader[0:])
	switch pefile.FileHeader.Machine {
	case IMAGE_FILE_MACHINE_AMD64,
		IMAGE_FILE_MACHINE_ARM64,
		IMAGE_FILE_MACHINE_ARMNT,
		IMAGE_FILE_MACHINE_I386,
		IMAGE_FILE_MACHINE_UNKNOWN:
		// ok
	default:
		return nil, fmt.Errorf("unrecognized PE machine: %#x", pefile.FileHeader.Machine)
	}
	// optionheader
	var optionheader = make([]byte,int64(pefile.FileHeader.SizeOfOptionalHeader))
	n,err := f.ReadAt(optionheader,int64(pefile.DosHeader.E_lfanew)+4+int64(binary.Size(pefile.FileHeader)))
	if n != int(pefile.FileHeader.SizeOfOptionalHeader){
		jlog.Error(n)
		return nil,fmt.Errorf("readed byte length less then SizeOfOptionalHeader")
	}
	if err != nil{
		jlog.Error(err)
		return nil,err
	}
	var opMinSz int
	pefile.OptionalHeader, err, opMinSz, pefile.Is32 = parseJIOH(optionheader)
	if err != nil{
		jlog.Error(err)
		return nil,err
	}
	pefile.DataDirectoryBase =  int64(pefile.DosHeader.E_lfanew)+4+int64(binary.Size(pefile.FileHeader)+opMinSz)
	//jlog.Debug(parseJINH(dosheader[0:],128))
	return

}
