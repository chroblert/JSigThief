package cmd

import (
	"jsigthief/core/jsignature"
	"fmt"
	"github.com/chroblert/jgoutils/jfile"
	"github.com/chroblert/jgoutils/jlog"
	"github.com/spf13/cobra"
	"strings"
	"time"
)

// signatureCmd represents the signature command
var AddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add Signature to File",
	Long: ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("signature called")
		if sigFile == "" || targetFile == ""{
			jlog.Error("请指定sig-file,target-file")
			return
		}
		if !strings.HasSuffix(sigFile,".sig"){
			jlog.Error("请指定.sig结尾的数字签名文件")
			return
		}
		if outputFile == ""{
			outputFile = inputFile+"-sig.exe"
		}
		if !strings.HasSuffix(outputFile,".exe"){
			outputFile = outputFile+".exe"
		}
		if ok,_ := jfile.PathExists(outputFile);ok{
			outputFile = strings.TrimRight(outputFile,".exe")+"-"+time.Now().Format("0102150405")+".exe"
		}
		err := jsignature.AddSig(sigFile,targetFile,outputFile)
		if err != nil{
			jlog.Error(err)
			return
		}
		jlog.Warnf("[+]signature %s was added to %s,stored at %s\n",sigFile,targetFile,outputFile)
	},
}

var sigFile string
func init() {
	AddCmd.Flags().StringVarP(&sigFile,"sig-file","s","","导出数字签名文件.sig")
	AddCmd.Flags().StringVarP(&targetFile,"target-file","t","","要添加数字签名的没有数字签名的PE文件")
	AddCmd.Flags().StringVarP(&outputFile,"output-file","o","","添加数字签名完成后的文件的保存路径")
}

