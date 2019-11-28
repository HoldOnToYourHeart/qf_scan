import socket
from threading import Thread, Semaphore

sm = Semaphore(20)
timeout = 5.0
# 超时判断
socket.setdefaulttimeout(timeout)


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


def get_ip_list(domain):  # 获取域名解析出的IP列表
    dict = {}
    with sm:
        try:
            addrs = socket.getaddrinfo(domain, None)
            for item in addrs:
                if item[4][0] in dict:
                    dict.get(domain).append(str(item[4][0]))
                else:
                    dict.setdefault(domain, []).append(str(item[4][0]))
            # print('[*] Url: {} IP: {}'.format(domain, dict[domain][0]))
        except Exception as e:
            print('[-] Error: {} info: {}'.format(domain, e))
            pass
        except socket.timeout as e:
            print('[-] {} time out'.format(domain))
            pass
    return dict


def open_url_txt(filename):
    url_list = []
    with open(filename, 'r') as f:
        for l in f:
            url_list.append(l.strip())
    return url_list


def save_info(url, ip, key):
    if key == 1:
        with open('url_ip.csv', 'a+') as f:
            url_info = url + ',' + ip + '\n'
            f.write(url_info)

    else:
        with open('error_info.txt', 'a+') as f:
            f.write(url + ' ' + ','.join(ip) + '\n')


if __name__ == '__main__':
    url_list = open_url_txt('url_list.txt')
    thread_list = []
    for url in url_list:
        t = ThreadWithReturnValue(target=get_ip_list, args=(url,))
        thread_list.append(t)
        t.start()
    for t in thread_list:
        ip = t.join()
        if ip:
            for key in ip:
                if len(ip[key]) > 1:
                    print('[-] The Url: {} Maybe Exist CDN'.format(key))
                    save_info(key, ip[key], 0)
                else:
                    print('[*] Url:{} IP:{}'.format(key, ip[key][0]))
                    save_info(key, ip[key][0], 1)
    print('[*] End Scanner')
