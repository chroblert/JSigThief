package pe

import "github.com/chroblert/jgoutils/jlog"

// 共占用F8H大小的字节
type IMAGE_NT_HEADER32 struct {
	Signature      uint32            // PE Signature: 50450000("PE"00)
	FileHeader     IMAGE_FILE_HEADER // 20B => 14H
	OptionalHeader IMAGE_OPTIONAL_HEADER32
}

type J_IMAGE_NT_HEADER32 struct {
	Signature      []uint8            // PE Signature: 50450000("PE"00)
	FileHeader     IMAGE_FILE_HEADER // 20B => 14H
	OptionalHeader IMAGE_OPTIONAL_HEADER32
}

// peBytes: PE文件的二进制流
// off: DOS_Header中的e_lfanew
func parseJINH(peBytes []byte,off uint32)(jinh *J_IMAGE_NT_HEADER32,err error){
	jinh = new(J_IMAGE_NT_HEADER32)
	jlog.Debug(len(peBytes))
	jinh.Signature = peBytes[off:off+4]
	return jinh, err
}