#!/usr/bin/python
#-*- coding:utf-8 -*-

'''
----------------------------------------------------
aclAuditor
批量审计网络设备配置，发现ACL列表中存在安全隐患的规则
Author: cahi1l1yn
Version:v1.0
--------------------------------------------------
'''



import os
import re

dport = ['135','139','445','21','23','67','68','69','3389','1433','1521','3306','telnet','ftp','mysql','oracle','sqlserver']
path = r'/Users/cahi1i1yn/workfile/git/test/'
output = r'/Users/cahi1i1yn/workfile/git/'

def pretreat(i):
    global alist
    txt = open(path+i).read()
    f = txt.find('acl')
    s = txt.rfind('acl')
    t = txt[s:].find('#')+s
    alist = txt[f:t].split('#')
    return alist

def ruleA(i):
    global c
    try:
        if re.search('udp',i) and re.search('permit',i):
            info = '[存在危险规则]开放了UDP协议：'+ i
            print(info)
            log.write(info+'\n')
            c += 1
    except:
        pass  
    try: 
        if re.search('source\s\d+.\d+.\d+.0|source\s\d+.\d+.0.0',i) and re.search('permit',i):
            info = '[存在宽松规则]源地址范围过大：'+ i
            print(info)
            log.write(info+'\n')
            c += 1
    except:
        pass 
    try:    
        if re.search('destination\s\d+.\d+.\d+.0|destination\s\d+.\d+.0.0',i) and re.search('permit',i):
            info = '[存在宽松规则]目的地址范围过大：'+ i
            print(info)
            log.write(info+'\n')
            c += 1
    except:
        pass  
    try:
        if re.search('eq\s\d+',i) and re.search('permit',i):
            if re.search('eq\s\d+',i).group().lstrip('eq ') in dport:
                info = '[存在危险规则]开放了危险端口：'+ i
                print(info)
                log.write(info+'\n')
                c += 1
    except:
        pass
    try:  
        if re.search('permit',i) and re.search('destination',i) and not re.search('source',i):
            info = '[存在宽松规则]未指定源地址：'+ i
            print(info)
            log.write(info +'\n')
            c += 1
    except:
        pass  
    try:   
        if re.search('permit',i) and re.search('source',i) and not re.search('destination',i):
            info = '[存在宽松规则]未指定目的地址：'+ i
            print(info)
            log.write(info +'\n')
            c += 1
    except:
        pass
    try: 
        if not re.search('eq',i) and not re.search('range',i) and re.search('permit',i):
            info = '[存在宽松规则]未指定端口：'+ i
            print(info)
            log.write(info +'\n')
            c += 1
    except:
        pass  
    try:     
        if re.search('permit',i) and re.search('any',i):
            info = '[存在宽松规则]开放了Any地址：'+ i
            print(info)
            log.write(info +'\n')
            c += 1
    except:
        pass  

def ruleB(i,o):
    global c
    if re.search('rule\s\d+',i).group() != re.search('rule\s\d+',o).group():
        if re.search('permit|deny',i).group() != re.search('permit|deny',o).group():
            try:
                if re.search('tcp|ip|udp|icmp',i).group() == re.search('tcp|ip|udp|icmp',o).group() \
                and re.search('source\s\d+.\d+.\d+.\d+',i).group() == re.search('source\s\d+.\d+.\d+.\d+',o).group() \
                and re.search('destination\s\d+.\d+.\d+.\d+',i).group() == re.search('destination\s\d+.\d+.\d+.\d+',o).group() \
                and re.search('eq\s\d+|range\s\d+\s\d+',i).group() == re.search('eq\s\d+|range\s\d+\s\d+',o).group():
                    info = '[存在冲突规则]相同地址和端口同时存在允许和禁止规则：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    c += 1
            except:
                pass
            try:
                if re.search('tcp|ip|udp|icmp',i).group() == re.search('tcp|ip|udp|icmp',o).group() \
                and re.search('source\s\d+.\d+.\d+.',i).group() == re.search('source\s\d+.\d+.\d+.',o).group() \
                and re.search('source\s\d+.\d+.\d+.0',i) \
                and re.search('destination\s\d+.\d+.\d+.\d+',i).group() == re.search('destination\s\d+.\d+.\d+.\d+',o).group() \
                and re.search('eq\s\d+|range\s\d+\s\d+',i).group() == re.search('eq\s\d+|range\s\d+\s\d+',o).group():
                    info = '[存在冲突规则]源地址冲突：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    c += 1
            except :
                pass
            try:        
                if re.search('tcp|ip|udp|icmp',i).group() == re.search('tcp|ip|udp|icmp',o).group() \
                and re.search('destination\s\d+.\d+.\d+.',i).group() == re.search('destination\s\d+.\d+.\d+.',o).group() \
                and re.search('destination\s\d+.\d+.\d+.0',i) \
                and re.search('source\s\d+.\d+.\d+.\d+',i).group() == re.search('source\s\d+.\d+.\d+.\d+',o).group() \
                and re.search('eq\s\d+|range\s\d+\s\d+',i).group() == re.search('eq\s\d+|range\s\d+\s\d+',o).group():
                    info = '[存在冲突规则]目的地址冲突：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    c += 1
            except :
                pass
        #-----------------------------------------------------------------------------------
        if re.search('permit|deny',i).group() == re.search('permit|deny',o).group():
            try:
                if re.search('tcp|ip|udp|icmp',i).group() == re.search('tcp|ip|udp|icmp',o).group() \
                and re.search('source\s\d+.\d+.\d+.\d+',i).group() == re.search('source\s\d+.\d+.\d+.\d+',o).group() \
                and re.search('destination\s\d+.\d+.\d+.\d+',i).group() == re.search('destination\s\d+.\d+.\d+.\d+',o).group() \
                and re.search('eq\s\d+|range\s\d+\s\d+',i).group() == re.search('eq\s\d+|range\s\d+\s\d+',o).group():
                    info = '[存在冗余规则]动作、源和目的地址、端口重复：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    c += 1
            except :
                pass
            try:
                if re.search('tcp|ip|udp|icmp',i).group() == re.search('tcp|ip|udp|icmp',o).group() \
                and re.search('source\s\d+.\d+.\d+.',i).group() == re.search('source\s\d+.\d+.\d+.',o).group() \
                and re.search('destination\s\d+.\d+.\d+.\d+',i).group() == re.search('destination\s\d+.\d+.\d+.\d+',o).group() \
                and re.search('source\s\d+.\d+.\d+.0|source\s\d+.\d+.0.0',i) \
                and re.search('eq\s\d+|range\s\d+\s\d+',i).group() == re.search('eq\s\d+|range\s\d+\s\d+',o).group():
                    info = '[存在覆盖规则]源地址被覆盖：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    c += 1
            except :
                pass
            try:
                if re.search('tcp|ip|udp|icmp',i).group() == re.search('tcp|ip|udp|icmp',o).group() \
                and re.search('source\s\d+.\d+.\d+.\d+',i).group() == re.search('source\s\d+.\d+.\d+.\d+',o).group() \
                and re.search('destination\s\d+.\d+.\d+.',i).group() == re.search('destination\s\d+.\d+.\d+.',o).group() \
                and re.search('destination\s\d+.\d+.\d+.0|destination\s\d+.\d+.0.0',i) \
                and re.search('eq\s\d+|range\s\d+\s\d+',i).group() == re.search('eq\s\d+|range\s\d+\s\d+',o).group():
                    info = '[存在覆盖规则]目的地址被覆盖：'+ i + '<||>' + o
                    print(info)
                    log.write(info+'\n')
                    c += 1
            except :
                pass

def main(path):
    global aname
    global log
    flist = os.listdir(path)
    for i in flist:
        pretreat(i)
        n = 0
        log = open(output+i+'.txt','a')
        while n < len(alist):
            acl = alist[n].split('\n')
            acl = [x.strip() for x in acl if x.strip() != '']
            try:
                global c
                c = 0
                aname = re.search('\w+$|\d+$',acl[0]).group()
                info = '------------------------------------------------\n[ACL]:'+aname+'\n[规则数量]:'+str((str(acl).count('rule')))
                print(info+'\n----------')
                log.write(info+'\n')
                dn =0
                if re.search('rule\s\d+\sdeny\sany\'\]$',str(acl)):
                    dn = 1
                else:
                    pass
                for i in acl:
                    if re.search('rule',i):
                        ruleA(i)
                        for o in acl:
                            if re.search('rule',o):
                                ruleB(i,o)
                        else:
                            pass
                if dn == 0:
                    info = '[未发现默认拒绝规则]'
                    log.write(info +'\n')
                    print(info)
                line = '\n------------------------------------------------\n||||||||||||||||||||||||||||||||||||||||||||||||'   
                info ='----------\n['+aname+']共发现安全隐患:'+str(c)+'项'+ line
                print(info)
                log.write(info +'\n')
            except IndexError:
                pass
            n += 1
    print('------------------------------------------------\n====================Finished====================')

    
if __name__ == '__main__':
    main(path)