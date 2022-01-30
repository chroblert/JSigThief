package pe

import "encoding/binary"

// IMAGE_DOS_HEADER: 占用64B
type IMAGE_DOS_HEADER struct {
	E_magic    uint16 // DOS签名 4D5A => MZ
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   uint32 // 指出NT头的偏移
}

type J_IMAGE_DOS_HEADER struct {
	E_magic    string // DOS签名 4D5A => MZ
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   uint32 // 指出NT头的偏移
}

func parseIDH(peBytes []byte)(jidh *J_IMAGE_DOS_HEADER){
	jidh = new(J_IMAGE_DOS_HEADER)
	jidh.E_magic = string(peBytes[0:2])
	jidh.E_cblp = binary.LittleEndian.Uint16(peBytes[2:])
	jidh.E_cp = binary.LittleEndian.Uint16(peBytes[4:])
	jidh.E_crlc = binary.LittleEndian.Uint16(peBytes[6:])
	jidh.E_cparhdr = binary.LittleEndian.Uint16(peBytes[8:])
	jidh.E_minalloc = binary.LittleEndian.Uint16(peBytes[10:])
	jidh.E_maxalloc = binary.LittleEndian.Uint16(peBytes[12:])
	jidh.E_ss = binary.LittleEndian.Uint16(peBytes[14:])
	jidh.E_sp = binary.LittleEndian.Uint16(peBytes[16:])
	jidh.E_csum = binary.LittleEndian.Uint16(peBytes[18:])
	jidh.E_ip = binary.LittleEndian.Uint16(peBytes[20:])
	jidh.E_cs = binary.LittleEndian.Uint16(peBytes[22:])
	jidh.E_lfarlc = binary.LittleEndian.Uint16(peBytes[24:])
	jidh.E_ovno = binary.LittleEndian.Uint16(peBytes[26:])
	jidh.E_res[0] = binary.LittleEndian.Uint16(peBytes[28:])
	jidh.E_res[1] = binary.LittleEndian.Uint16(peBytes[30:])
	jidh.E_res[2] = binary.LittleEndian.Uint16(peBytes[32:])
	jidh.E_res[3] = binary.LittleEndian.Uint16(peBytes[34:])
	jidh.E_oemid = binary.LittleEndian.Uint16(peBytes[36:])
	jidh.E_oeminfo = binary.LittleEndian.Uint16(peBytes[38:])
	jidh.E_res2[0] = binary.LittleEndian.Uint16(peBytes[40:])
	jidh.E_res2[1] = binary.LittleEndian.Uint16(peBytes[42:])
	jidh.E_res2[2] = binary.LittleEndian.Uint16(peBytes[44:])
	jidh.E_res2[3] = binary.LittleEndian.Uint16(peBytes[46:])
	jidh.E_res2[4] = binary.LittleEndian.Uint16(peBytes[48:])
	jidh.E_res2[5] = binary.LittleEndian.Uint16(peBytes[50:])
	jidh.E_res2[6] = binary.LittleEndian.Uint16(peBytes[52:])
	jidh.E_res2[7] = binary.LittleEndian.Uint16(peBytes[54:])
	jidh.E_res2[8] = binary.LittleEndian.Uint16(peBytes[56:])
	jidh.E_res2[9] = binary.LittleEndian.Uint16(peBytes[58:])
	jidh.E_lfanew = binary.LittleEndian.Uint32(peBytes[60:])
	return jidh
}