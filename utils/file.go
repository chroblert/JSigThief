package utils

import (
	"io"
	"os"
)

func FileCopy(src string,dst string)(error){
	srcf,err := os.Open(src)
	if err != nil{
		return err
	}
	defer srcf.Close()
	dstf,err := os.OpenFile(dst,os.O_RDWR|os.O_CREATE,0755)
	if err != nil{
		return err
	}
	defer dstf.Close()
	buf := make([]byte,500)
	for{
		n,err := srcf.Read(buf)
		if err != nil && err != io.EOF{
			return err
		}
		if n == 0{
			break
		}
		if _,err := dstf.Write(buf[:n]); err != nil{
			return err
		}
	}
	return nil
}