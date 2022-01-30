package cmd

import (
	"jsigthief/core/jsignature"
	"fmt"
	"github.com/chroblert/jgoutils/jlog"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

// signatureCmd represents the signature command
var ExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export File's Signature",
	Long: ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("signature called")
		if inputFile == "" {
			jlog.Error("请指定input-file")
			return
		}
		if outputFile == ""{
			outputFile = inputFile+".sig"
		}
		if !strings.HasSuffix(outputFile,".sig"){
			outputFile = outputFile+".sig"
		}

		certBytes,err := jsignature.ExportSignature(inputFile)
		if err != nil{
			jlog.Error(err)
			return
		}
		f2,err := os.OpenFile(outputFile,os.O_CREATE|os.O_RDWR,0755)
		if err != nil{
			jlog.Error(err)
			return
		}
		defer f2.Close()
		f2.Write(certBytes)
		jlog.Warnf("[+]%s's signature were stored at %s\n",inputFile,outputFile)
	},
}

var(
	inputFile string
	targetFile string
	outputFile string
)
func init() {
	ExportCmd.Flags().StringVarP(&inputFile,"input-file","i","","具有数字签名的PE文件")
	//ExportCmd.Flags().StringVarP(&targetFile,"target-file","t","","要添加数字签名的没有数字签名的PE文件")
	ExportCmd.Flags().StringVarP(&outputFile,"output-file","o","","添加数字签名完成后的文件的保存路径")
}

