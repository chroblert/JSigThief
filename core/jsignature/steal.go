package jsignature

import (
	"jsigthief/utils"
	"jsigthief/utils/pe"
	"encoding/binary"
	"fmt"
	"github.com/chroblert/jgoutils/jlog"
	"io"
	"os"
)

func StealSigTo(inputFile,targetFile,outputFile string)(err error){
	if CheckIsSigned(targetFile){
		return fmt.Errorf("目标文件已做过数字签名")
	}
	if !CheckIsSigned(inputFile){
		return fmt.Errorf("input-file文件需要带有数字签名")
	}
	var(
		certTableLoc int64
		//certSize uint32
		//certLoc uint32
	)
	pefile,err := pe.Parse(targetFile)
	if err != nil{
		jlog.Error(err)
		return
	}
	if pefile.Is32{
		certTableLoc = pefile.DataDirectoryBase+4*8
		//certSize = pefile.OptionalHeader.(*pe.IMAGE_OPTIONAL_HEADER32).DataDirectory[4].Size
		//certLoc = pefile.OptionalHeader.(*pe.IMAGE_OPTIONAL_HEADER32).DataDirectory[4].VirtualAddress
	}else{
		certTableLoc = pefile.DataDirectoryBase+4*8
		//certSize = pefile.OptionalHeader.(*pe.IMAGE_OPTIONAL_HEADER64).DataDirectory[4].Size
		//certLoc = pefile.OptionalHeader.(*pe.IMAGE_OPTIONAL_HEADER64).DataDirectory[4].VirtualAddress
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
	certBytes,_ := ExportSignature(inputFile)
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
