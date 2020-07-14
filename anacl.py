#!/usr/bin/python
#-*- coding:utf-8 -*-

'''
----------------------------------------------------
anacl
Optimize your acl of network device
Author: cahi1l1yn
Version:v0.3Beta
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

def dempty(d):
	for key in list(d.keys()):
	    if not d.get(key):
	    	del d[key]
	return d

def parse(acl,aname):
    global l
    l = globals()[aname] = []
    for  i in acl:
        dn = '0'
        if re.search('permit\s\w+',i) and i.find('source') < 0:
            info = '[存在宽松策略]未指定源和目的地址：'+ i
            print(info)
            log.write(info +'\n')
        elif re.search('permit\s\w+',i) and i.find('any') > 0:
            info = '[存在宽松策略]指定了ANY地址：'+ i
            print(info)
            log.write(info +'\n')
        elif re.search('deny\s\w+',i) or re.search('rule\s\d+\sdeny',i) and i.find('source') < 0:
            dn = '1'
        else:
            d = {'Rule':'','Action':'','Proto':'','Source':'','Desti':'','Port':''}
            try:
                d['Rule']=re.search('rule\s\d+',i).group().lstrip('rule ')
            except AttributeError:
                pass
            try:
                d['Action']=re.search('deny|permit',i).group()
            except AttributeError:
                pass
            try:
                d['Proto']=re.search('tcp|udp|icmp|ip',i).group()
            except AttributeError:
                pass
            try:
                d['Source']=re.search('source\s\d+.\d+.\d+.\d+',i).group().lstrip('source ')
            except AttributeError:
                pass
            try: 
                d['Desti']=re.search('destination\s\d+.\d+.\d+.\d+',i).group().lstrip('destination ')
            except AttributeError:
                pass
            try:               
                d['Port']=re.search('eq\s\w+|eq\s\d+',i).group().lstrip('eq ')
            except AttributeError:
                pass
 #           dempty(d)
            l.append(d)
            pass
    if dn == '0':
        info = '[未发现默认拒绝策略！！！]'
        print('[WARNNIGN]' + info)
        log.write(info +'\n')        
    return l

def danger(k):
    if k['Proto'] == 'udp' and k['Action'] == 'permit':
        info = '[存在危险策略]开放了UDP协议：'+ str(k)
        print(info)
        log.write(info+'\n')
    elif re.search('\d+.\d+.\d+\.0',k['Source']) or re.search('\d+.\d+.0\.0',k['Source']) or re.search('\d+.0.0\.0',k['Source']) and k['Action'] == 'permit':
        info = '[存在宽松策略]源地址范围过大：'+ str(k)
        print(info)
        log.write(info+'\n')
    elif re.search('\d+.\d+.\d+\.0',k['Desti']) or re.search('\d+.\d+.0\.0',k['Desti']) or re.search('\d+.0.0\.0',k['Desti']) and k['Action'] == 'permit':
        info = '[存在宽松策略]目标地址范围过大：'+ str(k)
        print(info)
        log.write(info+'\n') 
    elif k['Port'] in dport and k['Action'] == 'permit':
        info = '[存在危险策略]开放了危险端口：'+ str(k)
        print(info)
        log.write(info+'\n')  

def repeated(k,j):
    if k['Rule'] != j['Rule']:
        if k['Action'] == j['Action']:
        	try:
        		if k['Proto'] == j['Proto'] and k['Source'] == j['Source'] and k['Desti'] == j['Desti'] and k['Port'] == j['Port']:
        			info = '[存在冗余策略]动作、源和目标地址、端口重复：'+ str(k) + '||' + str (j)
        			print(info)
        			log.write(info+'\n')
        	except AttributeError:
        		pass
        	try:
        		if re.search('\d+.\d+.\d+',k['Source']).group() == re.search('\d+.\d+.\d+',j['Source']).group() and re.search('\d+.\d+.\d+\.0',k['Source']) and k['Port'] == j['Port'] and k['Proto'] == j['Proto']:
        			info = '[存在覆盖策略]源地址被覆盖：'+ str(k) + '||' + str (j)
        			print(info)
        			log.write(info+'\n')
        	except AttributeError:
        		pass
        	try: 
        		if re.search('\d+.\d+.\d+',k['Desti']).group() == re.search('\d+.\d+.\d+',j['Desti']).group() and re.search('\d+.\d+.\d+\.0',k['Desti']) and k['Port'] == j['Port'] and k['Proto'] == j['Proto']:
        			info = '[存在覆盖策略]目标地址被覆盖：'+ str(k) + '||' + str (j)
        			print(info)
        			log.write(info+'\n')
        	except AttributeError:
        		pass
        if k['Action'] != j['Action']:
        	try:
        		if k['Proto'] == j['Proto'] and k['Source'] == j['Source'] and k['Desti'] == j['Desti'] and k['Port'] == j['Port']:
        			info = '[存在冲突策略]相同地址和端口同时存在允许和禁止策略：'+ str(k) + '||' + str (j)
        			print(info)
        			log.write(info+'\n')
        	except AttributeError:
        		pass
        	try:
        		if re.search('\d+.\d+.\d+',k['Source']).group() == re.search('\d+.\d+.\d+',j['Source']).group() and re.search('\d+.\d+.\d+\.0',k['Source']) and k['Port'] == j['Port'] and k['Proto'] == j['Proto']:
        			info = '[存在冲突策略]源地址被冲突：'+ str(k) + '||' + str (j)
        			print(info)
        			log.write(info+'\n')
        	except AttributeError:
        		pass
        	try:
        		if re.search('\d+.\d+.\d+',k['Desti']).group() == re.search('\d+.\d+.\d+',j['Desti']).group() and re.search('\d+.\d+.\d+\.0',k['Desti']) and k['Port'] == j['Port'] and k['Proto'] == j['Proto']:
        			info = '[存在冲突策略]目标地址被冲突：'+ str(k) + '||' + str (j)
        			print(info)
        			log.write(info+'\n')
        	except AttributeError:
        		pass

def main(path):
    global aname
    global log
    flist = os.listdir(path)
    for i in flist:
        pretreat(i)
        n = 0
        while n < len(alist):
            acl = alist[n].split('\n')
            acl = [x.strip() for x in acl if x.strip() != '']
            print acl
            try:
                aname = re.search('\w+$|\d+$',acl[0]).group()
                info = '[INFO]ACL found:'+aname
                print(info)
                log = open(output+i+'.txt','a')
                log.write(info+'\n')
                parse(acl,aname)
                del l[0]
                print(l)
                for k in l:
                    danger(k)
                    for j in l:
                        repeated(k,j)
            except IndexError:
                pass
            n += 1
            print('---------------------')
    print('Finished........!')
if __name__ == '__main__':
    main(path)