import os
import re
import nmap
import getopt
import sys
import datetime
from threading import Thread, Semaphore

sm = Semaphore(20)
target_t = False
file_t = False
target = ""
file_name = ""
info_list = [[['ip','port','state','name','product','version']]]
error_ip = []

class ThreadWithReturnValue(Thread):
    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None, *, daemon=None):
        Thread.__init__(self, group, target, name, args, kwargs, daemon=daemon)
        self._return = None
    def run(self):
        if self._target is not None:
                self._return = self._target(*self._args,**self._kwargs)
    def join(self):
        Thread.join(self)
        return self._return

def usage():
    print ("port_scan.py -t 127.0.0.1")
    print ("port_scan.py -f ip_list.txt")
    sys.exit(0)

def main():
    global target_t
    global file_t
    global target
    global file_name

    if not len(sys.argv[1:]):
        usage()
    try:
        opts, args = getopt.getopt(sys.argv[1:],'ht:f:',['help','target','file'])
    except getopt.GetoptError as a:
        usage()
    
    for o, a in opts:
        if o in ('-h','--help'):
            usage()
        elif o in ('-t','--target'):
            target_t = True
            target = a
        elif o in ('-f','--file'):
            file_t = True
            file_name = a
        else:
            assert False, "Unhandled Options"
    
    if not file_t and len(target) > 0:
        one(target,target_t)
    if file_t:
        more(file_name,file_t)

def one(target, target_t):
    ip = target
    data = masscan_scan(ip, target_t, file_t)
    for ip in data:
        port = ','.join(data[ip])
        nmap_scan(ip,port)

def more(file_name, file_t):
    global info_list
    thread_list = []
    data = masscan_scan(file_name, target_t, file_t)
    i = 0
    for ip in data:
        i = i + 1
        port = ','.join(data[ip])
        # print('[*]' + str(len(data[ip])))
        if len(data[ip]) < 120:
            t = ThreadWithReturnValue(target=nmap_scan,args=(ip, port))
            thread_list.append(t)
            t.start()
        else:
            print ('[*] error_ip: ' + ip)
            with open('error_ip.txt','a+') as f:
                    f.write(str(ip) + '\n')
    print('[*] SUM ' + str(i))
    for t in thread_list:
        aa = t.join()
        info_list.append(aa)
    


def masscan_scan(ip,t,f):
    if t and not f:
        print ('[*] Masscan_Scaner ' + ip )
        os.system('sudo masscan ' + ip + ' -p 1-65535 -oG port_info.txt --rate=2000')
    else:
        print ('[*] Masscan_Scaner ' + ip )
        os.system('sudo masscan -iL ' + ip + ' -p 1-65535 -oG port_info.txt --rate=2000')
    f1 = open("test.txt", 'r')
    re1 = 'Host\:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\(\)\s+Ports\:\s+(\d+)/open'
    ip_port = []
    ips_list = []
    data = {}
    for line in f1:
        res = re.findall(re1, line.strip())
        if res:
            ip_port.append((res[0][0], int(res[0][1])))
            ips_list.append(res[0][0])
    ips_list = list(set(ips_list))
    ip_port = list(set(ip_port))
    i = 0
    for info in ip_port:
        i = i + 1
        if info[0] in data:
            data.get(info[0]).append(str(info[1]))
        else:
            data.setdefault(info[0], []).append(str(info[1]))
    print ('[*] sum ' + str(i))
    return data

def nmap_scan(ip, port):
    global info_list
    tmp_info =[]
    with sm:
        for p in port.split(','):
            print ('[*] Nmap_Scaner ' +  ip + ' port '+ p)
            nm = nmap.PortScanner()
            ret = nm.scan(ip, p, arguments='-sV -T5 -Pn')
            if ret['scan'][ip]['tcp'][int(p)]:
                state = ret['scan'][ip]['tcp'][int(p)]['state']
                product = ret['scan'][ip]['tcp'][int(p)]['product']
                version = ret['scan'][ip]['tcp'][int(p)]['version']
                name = ret['scan'][ip]['tcp'][int(p)]['name']
                print ('[*] IP:{},Port:{},State:{},Name:{},Product:{},Version:{}'.format(ip, p, state, name, product, version))
                tmp_info.append([ip,p,state,name,product,version])
    return tmp_info


if __name__ == "__main__":
    main()
    print('[*] end_scan')
    print (info_list)
    with open('port_info.csv', 'w+') as f:
        for i in info_list:
            if i:
                for j in i:
                    str1 = ','.join(j)
                    f.write(str1 + '\n')
