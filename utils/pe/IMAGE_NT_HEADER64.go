package pe

type IMAGE_NT_HEADER64 struct {
	Signature      [4]byte            // PE Signature: 50450000("PE"00)
	FileHeader     IMAGE_FILE_HEADER // 20B => 14H
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}
