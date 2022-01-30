package cmd

import (
	"jsigthief/core/jsignature"
	"github.com/chroblert/jgoutils/jfile"
	"github.com/chroblert/jgoutils/jlog"
	"github.com/spf13/cobra"
	"strings"
	"time"
)

// signatureCmd represents the signature command
var StealCmd = &cobra.Command{
	Use:   "steal",
	Short: "Steal signature from File A,then add signature to File B",
	Long: ``,
	Run: func(cmd *cobra.Command, args []string) {
		//fmt.Println("signature called")
		if inputFile == "" || targetFile == ""{
			jlog.Error("请指定input-file,target-file")
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
		err := jsignature.StealSigTo(inputFile,targetFile,outputFile)
		if err != nil{
			jlog.Error(err)
			return
		}
		jlog.Warnf("[+]steal signature from %s to  %s,output is %s\n",inputFile,targetFile,outputFile)
	},
}

func init() {
	StealCmd.Flags().StringVarP(&inputFile,"input-file","i","","带有数字签名的PE文件")
	StealCmd.Flags().StringVarP(&targetFile,"target-file","t","","要添加数字签名的没有数字签名的PE文件")
	StealCmd.Flags().StringVarP(&outputFile,"output-file","o","","添加数字签名完成后的文件的保存路径")
}
