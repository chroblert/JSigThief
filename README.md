JSigThief

## 介绍
原版是python语言编写的，现在用golang写一版SigThief,
本工具属于JBypass免杀系列的其中一个工具。

本工具实现了python版sigthief中的大部分功能，目前只支持对exe程序进行签名提权和添加...

## 使用
![](https://gitee.com/chroblert/pictures/raw/master/img/img.png)

### 检查某程序是否有签名
`jsigthief.exe check -i <具体文件路径>`
![](https://gitee.com/chroblert/pictures/raw/master/img/20220130231929.png)

### 导出已签名程序的数字签名
`jsigthief.exe export -i <已签名文件路径> -o <导出路径>`
![](https://gitee.com/chroblert/pictures/raw/master/img/20220130232112.png)

### 向目标文件添加导出的数字签名
`jsigthief.exe add -s <导出的.sig文件> -t <待添加签名的程序> -o <签名后输出路径>`
![](https://gitee.com/chroblert/pictures/raw/master/img/20220130232328.png)

### 直接偷取某程序的签名并添加到待签名的程序中
`jsigthief.exe -i <带有数字签名的PE文件> -t <待签名的PE文件> -o <签名后的输出路径>`
![](https://gitee.com/chroblert/pictures/raw/master/img/20220130232737.png)