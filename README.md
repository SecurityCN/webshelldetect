# HVV必备蓝方Webshell 查杀工具
# webshelldetect  
正式版v1.0   
1.兼容py2 py3  
2.解决中文乱码错误，兼容windows和linux  
3.全部依赖改为python标准库,无需安装第三方库，可直接在装作python环境的服务器运行（兼容windows和linux）  
4.支持查杀单个文件或目录，且目录查杀支持自定义文件修改时间范围 格式为20190101 20200820 或  201901010101 202008202359  
5.支持自定义恶意代码规则  
6.默认查找模式为找到恶意代码规则库中其中一个就结束，如果需要继续遍历请注释59行break

使用1:查杀单个文件：  
`python webshelldetect_v1.py <文件名> `

使用2:查杀目录,支持自定义文件修改时间范围 格式为20200101 20200830缺省为当前时间  
`python webshelldetect_v1.py <目录名> [文件修改时间开始如：20200101] [文件修改时间结束如：20200820,缺省为当前时间]`

# 演示：
![demo](https://raw.githubusercontent.com/SecurityCN/webshelldetect/master/demo.png)
