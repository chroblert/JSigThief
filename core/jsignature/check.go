package jsignature

import (
	"jsigthief/utils/pe"
	"github.com/chroblert/jgoutils/jlog"
)

func CheckIsSigned(ifile string)(b bool){
	b = false
	// 判断i文件是否为PE文件，是否带签名
	pefile,err := pe.Parse(ifile)
	if err != nil{
		jlog.Error(err)
		return
	}
	var(
		//certTableLoc int64
		certSize uint32
		certLoc uint32
	)
	if pefile.Is32{
		//certTableLoc = pefile.DataDirectoryBase+4*8
		certSize = pefile.OptionalHeader.(*pe.IMAGE_OPTIONAL_HEADER32).DataDirectory[4].Size
		certLoc = pefile.OptionalHeader.(*pe.IMAGE_OPTIONAL_HEADER32).DataDirectory[4].VirtualAddress
	}else{
		//certTableLoc = pefile.DataDirectoryBase+4*8
		certSize = pefile.OptionalHeader.(*pe.IMAGE_OPTIONAL_HEADER64).DataDirectory[4].Size
		certLoc = pefile.OptionalHeader.(*pe.IMAGE_OPTIONAL_HEADER64).DataDirectory[4].VirtualAddress
	}
	if certSize == 0x0 || certLoc == 0x0 {
		//jlog.Error("[!]请指定带有数字签名的PE文件")
		return
	}else{
		return true
	}

}
