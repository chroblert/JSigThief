package pe

import (
	"encoding/binary"
	"fmt"
	"io"
)

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

// readDataDirectories accepts a io.ReadSeeker pointing to data directories in the PE file,
// its size and number of data directories as seen in optional header.
// It parses the given size of bytes and returns given number of data directories.
func readDataDirectories(r io.ReadSeeker, sz uint16, n uint32) ([]IMAGE_DATA_DIRECTORY, error) {
	ddSz := binary.Size(IMAGE_DATA_DIRECTORY{})
	if uint32(sz) != n*uint32(ddSz) {
		return nil, fmt.Errorf("size of data directories(%d) is inconsistent with number of data directories(%d)", sz, n)
	}

	dd := make([]IMAGE_DATA_DIRECTORY, n)
	if err := binary.Read(r, binary.LittleEndian, dd); err != nil {
		return nil, fmt.Errorf("failure to read data directories: %v", err)
	}

	return dd, nil
}
