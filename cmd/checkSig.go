package cmd

import (
	"jsigthief/core/jsignature"
	"fmt"
	"github.com/chroblert/jgoutils/jlog"
	"github.com/spf13/cobra"
)

// signatureCmd represents the signature command
var CheckCmd = &cobra.Command{
	Use:   "check",
	Short: "check file if is signed",
	Long: ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("signature called")
		if inputFile == "" {
			jlog.Error("请指定input-file")
			return
		}
		if jsignature.CheckIsSigned(inputFile){
			jlog.Warnf("[+]file %s was signed\n",inputFile)
		}else{
			jlog.Warnf("[+]file %s not signed\n",inputFile)
		}
	},
}

func init() {
	CheckCmd.Flags().StringVarP(&inputFile,"input-file","i","","PE文件")
}


