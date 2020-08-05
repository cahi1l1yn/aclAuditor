#!/usr/bin/python
#-*- coding:utf-8 -*-

'''
----------------------------------------------------
aclAuditor
批量审计网络设备配置，发现ACL列表中存在安全隐患的规则
Author: cahi1l1yn
Version:v2.0
--------------------------------------------------
'''



import os
import re

dport = ['135','139','445','21','23','67','68','69','3389','1433','1521','3306','telnet','ftp','mysql','oracle','sqlserver']
path = r''
output = r''
line = '------------------------------------------------'

def pretreat(file):
    global acl_list
    global device_type
    txt = open(path+file).read()
    if 'ip access-list' in txt:
        first_index = txt.find('ip access')
        second_index = txt.rfind('ip access')
        third_index = txt[second_index:].find('!')+second_index
        acl_list = txt[first_index:third_index].split('!')
        device_type = 'cisco'
    else:
        first_index = txt.find('acl')
        second_index = txt.rfind('acl')
        third_index = txt[second_index:].find('#')+second_index
        acl_list = txt[first_index:third_index].split('#')
        device_type = 'huawei'


def ruleA1(i):
    global match_count
    try:
        if re.search(r'udp',i) and re.search(r'permit',i):
            info = '[存在危险规则]开放了UDP协议：'+ i
            print(info)
            log.write(info+'\n')
            match_count += 1
    except:
        pass  
    try: 
        if re.search(r'source\s(\d+\.){3}0|source\s\(\d+\.){2}0.0',i) and re.search(r'permit',i):
            info = '[存在宽松规则]源地址范围过大：'+ i
            print(info)
            log.write(info+'\n')
            match_count += 1
    except:
        pass 
    try:    
        if re.search(r'destination\s(\d+\.){3}0|destination\s\(\d+\.){2}0.0',i) and re.search(r'permit',i):
            info = '[存在宽松规则]目的地址范围过大：'+ i
            print(info)
            log.write(info+'\n')
            match_count += 1
    except:
        pass  
    try:
        if re.search(r'eq\s\d+',i) and re.search(r'permit',i):
            if re.search(r'eq\s\d+',i).group().lstrip('eq ') in dport:
                info = '[存在危险规则]开放了危险端口：'+ i
                print(info)
                log.write(info+'\n')
                match_count += 1
    except:
        pass
    try:  
        if re.search(r'permit',i) and re.search(r'destination',i) and not re.search(r'source',i):
            info = '[存在宽松规则]未指定源地址：'+ i
            print(info)
            log.write(info +'\n')
            match_count += 1
    except:
        pass  
    try:   
        if re.search(r'permit',i) and re.search(r'source',i) and not re.search(r'destination',i):
            info = '[存在宽松规则]未指定目的地址：'+ i
            print(info)
            log.write(info +'\n')
            match_count += 1
    except:
        pass
    try: 
        if not re.search(r'eq',i) and not re.search(r'range',i) and re.search(r'permit',i) and not re.search(r'any',i):
            info = '[存在宽松规则]未指定端口：'+ i
            print(info)
            log.write(info +'\n')
            match_count += 1
    except:
        pass  
    try:     
        if re.search(r'permit',i) and re.search(r'any',i):
            info = '[存在宽松规则]开放了Any地址：'+ i
            print(info)
            log.write(info +'\n')
            match_count += 1
    except:
        pass  

def ruleA2(i,o):
    global match_count
    if re.search(r'rule\s\d+',i).group() != re.search(r'rule\s\d+',o).group():
        if re.search(r'permit|deny',i).group() != re.search(r'permit|deny',o).group():
            try:
                if re.search(r'tcp|ip|udp|icmp',i).group() == re.search(r'tcp|ip|udp|icmp',o).group() \
                and re.search(r'source\s\s(\d+\.){3}\d+',i).group() == re.search(r'source\s(\d+\.){3}\d+',o).group() \
                and re.search(r'destination\s\s(\d+\.){3}\d+',i).group() == re.search(r'destination\s(\d+\.){3}\d+',o).group() \
                and re.search(r'eq\s\d+|range\s[\d+\s]*',i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*',o).group():
                    info = '[存在冲突规则]相同地址和端口同时存在允许和禁止规则：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    match_count += 1
            except:
                pass
            try:
                if re.search(r'tcp|ip|udp|icmp',i).group() == re.search(r'tcp|ip|udp|icmp',o).group() \
                and re.search(r'source\s(\d+\.){3}\d+',i).group() == re.search(r'source\s(\d+\.){3}\d+',o).group() \
                and re.search(r'destination\s(\d+\.){3}\d+',i).group() == re.search(r'destination\s(\d+\.){3}\d+',o).group() \
                and re.search(r'eq\s\d+|range\s[\d+\s]*',i).group() != re.search(r'eq\s\d+|range\s[\d+\s]*',o).group():
                    info = '[存在冲突规则]端口被冲突：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    match_count += 1
            except:
                pass  
            try:
                if re.search(r'tcp|ip|udp|icmp',i).group() == re.search(r'tcp|ip|udp|icmp',o).group() \
                and re.search(r'source\s(\d+\.){3}',i).group() == re.search(r'source\s(\d+\.){3}',o).group() \
                and re.search(r'source\s(\d+\.){3}0',i) \
                and re.search(r'destination\s(\d+\.){3}\d+',i).group() == re.search(r'destination\s(\d+\.){3}\d+',o).group() \
                and re.search(r'eq\s\d+|range\s[\d+\s]*',i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*',o).group():
                    info = '[存在冲突规则]源地址冲突：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    match_count += 1
            except :
                pass
            try:        
                if re.search(r'tcp|ip|udp|icmp',i).group() == re.search(r'tcp|ip|udp|icmp',o).group() \
                and re.search(r'destination\s(\d+\.){3}',i).group() == re.search(r'destination\s(\d+\.){3}',o).group() \
                and re.search(r'destination\s(\d+\.){3}0',i) \
                and re.search(r'source\s(\d+\.){3}\d+',i).group() == re.search(r'source\s(\d+\.){3}\d+',o).group() \
                and re.search(r'eq\s\d+|range\s[\d+\s]*',i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*',o).group():
                    info = '[存在冲突规则]目的地址冲突：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    match_count += 1
            except :
                pass
        #-----------------------------------------------------------------------------------
        elif re.search(r'permit|deny',i).group() == re.search(r'permit|deny',o).group():
            try:
                if re.search(r'tcp|ip|udp|icmp',i).group() == re.search(r'tcp|ip|udp|icmp',o).group() \
                and re.search(r'source\s(\d+\.){3}\d+',i).group() == re.search(r'source\s(\d+\.){3}\d+',o).group() \
                and re.search(r'destination\s(\d+\.){3}\d+',i).group() == re.search(r'destination\s(\d+\.){3}\d+',o).group() \
                and re.search(r'eq\s\d+|range\s[\d+\s]*',i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*',o).group():
                    info = '[存在冗余规则]动作、源和目的地址、端口重复：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    match_count += 1
            except :
                pass
            try:
                if re.search(r'tcp|ip|udp|icmp',i).group() == re.search(r'tcp|ip|udp|icmp',o).group() \
                and re.search(r'source\s(\d+\.){3}',i).group() == re.search(r'source\s(\d+\.){3}',o).group() \
                and re.search(r'destination\s(\d+\.){3}\d+',i).group() == re.search(r'destination\s(\d+\.){3}\d+',o).group() \
                and re.search(r'source\s(\d+\.){3}0|source\s(\d+\.){2,}0.0',i) \
                and re.search(r'eq\s\d+|range\s[\d+\s]*',i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*',o).group():
                    info = '[存在覆盖规则]源地址被覆盖：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    match_count += 1
            except :
                pass
            try:
                if re.search(r'tcp|ip|udp|icmp',i).group() == re.search(r'tcp|ip|udp|icmp',o).group() \
                and re.search(r'source\s(\d+\.){3}\d+',i).group() == re.search(r'source\s(\d+\.){3}\d+',o).group() \
                and re.search(r'destination\s(\d+\.){3}',i).group() == re.search(r'destination\s(\d+\.){3}',o).group() \
                and re.search(r'destination\s(\d+\.){3}0|destination\s(\d+\.){2,}0.0',i) \
                and re.search(r'eq\s\d+|range\s[\d+\s]*',i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*',o).group():
                    info = '[存在覆盖规则]目的地址被覆盖：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    match_count += 1
            except :
                pass

def ruleB1(i):
    global match_count
    try:
        if re.search(r'udp',i) and re.search(r'permit',i):
            info = '[存在危险规则]开放了UDP协议：'+ i
            print(info)
            log.write(info+'\n')
            match_count += 1
    except:
        pass  
    try: 
        if re.search(r'((?<=tcp\s)|(?<=ip\s)|(?<=udp\s)|(?<=icmp\s))[host\s]*(\d+\.){3}0|((?<=tcp\s)|(?<=ip\s)|(?<=udp\s)|(?<=icmp\s))[host\s]*(\d+\.){2}0.0',i) \
        and re.search(r'permit',i):
            info = '[存在宽松规则]源地址范围过大：'+ i
            print(info)
            log.write(info+'\n')
            match_count += 1
    except:
        pass 
    try:    
        if re.search(r'\s(\d+\.){3}0\s\S+\seq|\s(\d+\.){2}0.0\s\S+\seq|\s(\d+\.){3}0\s\S+255$|\s(\d+\.){2}0+.0\s\S+255$',i) \
        and re.search(r'permit',i):
            info = '[存在宽松规则]目的地址范围过大：'+ i
            print(info)
            log.write(info+'\n')
            match_count += 1
    except:
        pass  
    try:
        if re.search(r'eq\s\d+',i) and re.search(r'permit',i):
            if re.search(r'eq\s\d+',i).group().lstrip('eq ') in dport:
                info = '[存在危险规则]开放了危险端口：'+ i
                print(info)
                log.write(info+'\n')
                match_count += 1
    except:
        pass 
    try:  
        if re.search(r'permit',i) and re.search(r'any\s[host]*\s*\d*.*',i):
            info = '[存在宽松规则]指定了ANY源地址：'+ i
            print(info)
            log.write(info +'\n')
            match_count += 1
    except:
        pass  
    try:   
        if re.search(r'permit',i) and re.search(r'\s\d+\.\d+\.\d+\.\d+\sany$',i) \
        and not re.search(r'destination',i):
            info = '[存在宽松规则]指定了ANY目的地址：'+ i
            print(info)
            log.write(info +'\n')
            match_count += 1
    except:
        pass
    try: 
        if not re.search(r'eq',i) and not re.search(r'range',i) and re.search(r'permit',i) and not re.search(r'any',i):
            info = '[存在宽松规则]未指定端口：'+ i
            print(info)
            log.write(info +'\n')
            match_count += 1
    except:
        pass  

def ruleB2(i,o):
    global match_count
    if acl.index(i) != acl.index(o):
        if re.search(r'permit|deny',i).group() != re.search(r'permit|deny',o).group():
            try:
                if re.search(r'tcp|ip|udp|icmp',i).group() == re.search(r'tcp|ip|udp|icmp',o).group() \
                and [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+',i) if '0.255' not in x][0] \
                == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+',o) if '0.255' not in x][0] \
                and [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+',i) if '0.255' not in x][1] \
                == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+',o) if '0.255' not in x][1] \
                and re.search(r'eq\s\d+|range\s[\d+\s]*',i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*',o).group():
                    info = '[存在冲突规则]相同地址和端口同时存在允许和禁止规则：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    match_count += 1
            except:
                pass               
            try:
                if [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.',i) if '0.0.0' not in x][0] \
                == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.',o) if '0.0.0' not in x][0] \
                and re.search(r'((?<=tcp\s)|(?<=ip\s)|(?<=udp\s)|(?<=icmp\s))[host\s]*(\d+\.){3}0',i) \
                and [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+',i) if '0.255' not in x][1] \
                == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+',o) if '0.255' not in x][1] \
                and re.search(r'eq\s\d+|range\s[\d+\s]*',i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*',o).group():
                    info = '[存在冲突规则]源地址冲突：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    match_count += 1
            except :
                pass
            try:        
                if [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+',i) if '0.255' not in x][0] \
                == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+',o) if '0.255' not in x][0] \
                and [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.',i) if '0.0.0' not in x][1] \
                == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.',o) if '0.0.0' not in x][1] \
                and re.search(r'(\d+\.){3}0',[x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+',i) if '0.255' not in x][1]).group() \
                and re.search(r'eq\s\d+|range\s[\d+\s]*',i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*',o).group():
                    info = '[存在冲突规则]目的地址冲突：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    match_count += 1
            except :
                pass
        #-----------------------------------------------------------------------------------
        elif re.search(r'permit|deny',i).group() == re.search(r'permit|deny',o).group(): 
            try:
                if [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.',i) if '0.0.0' not in x][0] \
                == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.',o) if '0.0.0' not in x][0] \
                and re.search(r'(tcp|udp|icmp)+\s[host\s]*(\d+\.){3}0',i) \
                and [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+',i) if '0.255' not in x][1] \
                == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+',o) if '0.255' not in x][1] \
                and re.search(r'eq\s\d+|range\s[\d+\s]*',i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*',o).group():
                    info = '[存在覆盖规则]源地址被覆盖：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    match_count += 1
            except :
                pass
            try:
                if [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+',i) if '0.255' not in x][0] \
                == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+',o) if '0.255' not in x][0] \
                and [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.',i) if '0.0.0' not in x][1] \
                == [x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.',o) if '0.0.0' not in x][1] \
                and re.search(r'(\d+\.){3}0',[x.strip() for x in re.findall(r'\d+\.\d+\.\d+\.\d+',i) if '0.255' not in x][1]).group() \
                and re.search(r'eq\s\d+|range\s[\d+\s]*',i).group() == re.search(r'eq\s\d+|range\s[\d+\s]*',o).group():
                    info = '[存在覆盖规则]目的地址被覆盖：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    match_count += 1
            except :
                pass

def main(path):
    global acl_name
    global log
    global acl
    file_list = os.listdir(path)
    for file in file_list:
        n = 0
        log = open(output+file+'.txt','a')
        file_name = file
        info = line + '\n配置文件['+file+']开始审计'
        print(info)
        log.write(info+'\n')
        pretreat(file)
        if device_type == 'huawei':
            acl_count = str(acl_list).count('acl')
        elif device_type =='cisco':
            acl_count = str(acl_list).count('ip access')
        global_count = 0
        while n < len(acl_list):
            acl = acl_list[n].split('\n')
            acl = [x.strip() for x in acl if x.strip() != '']
            try:
                global match_count
                match_count = 0
                acl_name = re.search(r'\w+$|\d+$',acl[0]).group()
                info = line + '\n[ACL]:'+acl_name+'\n[规则数量]:'+str(len(acl)-1)
                print(info+'\n----------')
                log.write(info+'\n')
                deny = 'fasle'
                if re.search(r'deny\sany\'\]$',str(acl)):
                    deny = 'true'
                else:
                    pass                
                if device_type == 'huawei':
                    for i in acl:
                        if re.search(r'rule',i):
                            ruleA1(i)
                            for o in acl:
                                if re.search(r'rule',o):
                                    ruleA2(i,o)
                            else:
                                pass
                elif device_type == 'cisco':
                    for i in acl:
                        if 'ip access-list' not in i:
                            ruleB1(i)
                            for o in acl:
                                if 'ip access-list' not in o:
                                    ruleB2(i,o)
                            else:
                                pass
                if deny == 'fasle':
                    info = '[未发现默认拒绝规则]'
                    log.write(info +'\n')
                    print(info)  
                info ='----------\n['+acl_name+']共发现安全隐患:'+str(match_count)+'项\n'+ line
                print(info)
                log.write(info +'\n')
            except IndexError:
                pass
            global_count += match_count
            n += 1
        info = '配置文件['+file_name+']'+'审计结束\nACL总数为['+str(acl_count)+']\n安全隐患总数为['+str(global_count)+']'
        print(info)
        log.write(info +'\n')
    print(line+'\n====================Finished====================')

    
if __name__ == '__main__':
    main(path)