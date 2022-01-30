package jsignature

import (
	"jsigthief/utils/pe"
	"fmt"
	"github.com/chroblert/jgoutils/jlog"
	"os"
)

func ExportSignature(ifile string)(cbytes []byte,err error){
	if !CheckIsSigned(ifile){
		return nil,fmt.Errorf("该文件没有数字签名")
	}
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
	f1,err := os.Open(ifile)
	if err != nil{
		jlog.Error(err)
		return
	}
	defer f1.Close()
	certBytes := make([]byte,certSize)
	n,err := f1.ReadAt(certBytes,int64(certLoc))
	if err != nil{
		jlog.Error(err,n)
		return
	}
	//cbytes = certBytes
	return certBytes,nil
}
