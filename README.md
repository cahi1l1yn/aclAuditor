# anacl
 Optimize your acl of network device


#使用方法 . 
使用前配置以下变量：    
dport为需要审计的端口，如21、3389、3306等定义为危险端口 .   
path为acl文件所在目录 .   
output为审计日志输出目录 .   
配置后直接运行脚本 .   

#注意事项 . 
审计规则基于华三设备的acl格式编写，其他品牌设备的acl格式如果相差太大的话可能无法审计。  
格式示例：  
rule 10 deny tcp source 172.19.8.0 0.0.0.255 destination 172.19.7.0 0.0.0.255 destination-port eq 22 . 

