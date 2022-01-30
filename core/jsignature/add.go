package jsignature

import (
	"jsigthief/utils"
	"jsigthief/utils/pe"
	"encoding/binary"
	"github.com/chroblert/jgoutils/jlog"
	"io"
	"os"
)

func AddSig(sigFile,targetFile,outputFile string)(err error){
	// 判断i文件是否为PE文件，是否带签名
	pefile,err := pe.Parse(targetFile)
	if err != nil{
		jlog.Error(err)
		return
	}
	var(
		certTableLoc int64
		certSize uint32
		certLoc uint32
	)
	if pefile.Is32{
		certTableLoc = pefile.DataDirectoryBase+4*8
		certSize = pefile.OptionalHeader.(*pe.IMAGE_OPTIONAL_HEADER32).DataDirectory[4].Size
		certLoc = pefile.OptionalHeader.(*pe.IMAGE_OPTIONAL_HEADER32).DataDirectory[4].VirtualAddress
	}else{
		certTableLoc = pefile.DataDirectoryBase+4*8
		certSize = pefile.OptionalHeader.(*pe.IMAGE_OPTIONAL_HEADER64).DataDirectory[4].Size
		certLoc = pefile.OptionalHeader.(*pe.IMAGE_OPTIONAL_HEADER64).DataDirectory[4].VirtualAddress
	}
	//jlog.Debugf("%08x,%08x,%08x",certTableLoc,certSize,certLoc)
	// 目标文件应该没有数字签名
	if !(certSize == 0x0 && certLoc == 0x0) {
		jlog.Error("[!]请指定不带有数字签名的PE文件")
		return
	}
	// 打开签名文件
	f1,err := os.Open(sigFile)
	if err != nil{
		jlog.Error(err)
		return
	}
	defer f1.Close()
	fi,err := f1.Stat()
	if err != nil{
		jlog.Error(err)
		return
	}
	// 保存数字签名信息
	certBytes := make([]byte,fi.Size())
	n,err := f1.Read(certBytes)
	if err != nil{
		jlog.Error(err,n)
		return
	}
	// 复制文件
	if err := utils.FileCopy(targetFile,outputFile);err != nil{
		jlog.Error(err)
		return err
	}
	//
	f2,err := os.OpenFile(outputFile,os.O_RDWR,0755)
	if err != nil{
		jlog.Error(err)
		return
	}
	defer f2.Close()
	f2i,err := f2.Stat()
	if err != nil{
		jlog.Error(err)
		return
	}
	f2.Seek(0,io.SeekEnd)
	f2.Write(certBytes)
	f2.Seek(certTableLoc,io.SeekStart)
	// 写入rva
	//f2.Write([]byte(f2i.Size()))
	binary.Write(f2,binary.LittleEndian,uint32(f2i.Size()))
	// 写入size
	//f2.Write(len(certBytes))
	binary.Write(f2,binary.LittleEndian,uint32(len(certBytes)))
	return nil
}
