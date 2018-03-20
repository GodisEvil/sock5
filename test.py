#!python
#-*- coding: utf-8 -*-
'''
	测试
'''

import socks
import socket
import binascii
import struct

def testNoauth():
    s = socks.socksocket()
    # s.set_proxy(socks.SOCKS5, "www.admobnet.com", 9999)
    s.set_proxy(socks.SOCKS5, "api.linkcel.com", 10000)
    s.connect(('www.baidu.com', 80))
    # s.connect(('api.linkcel.com', 80))
    s.settimeout(60)
    s.send(b'GET /s?ie=UTF-8&wd=ip HTTP/1.1\r\nHost:www.baidu.com\r\n\r\n')
    while 1:
        data = s.recv(2048)
        if data:
            print(data)
        else:
            break
    return True


def testAuth(uname, passwd, mode):
    '''
    测试认证的 socks5
    :return:
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(60)
    s.connect(('api.linkcel.com', 9999))
    s.send(b'\x05\x01\x02')
    resp = s.recv(1024)
    if resp != b'\x05\x02':
        print('method is not supported, returnd ' + binascii.b2a_hex(resp))
        return False
    ## 认证
    ulen = len(uname)
    sendData = b'\x05' + struct.pack('B%dsB%ds' % (ulen, len(passwd)), ulen, uname, len(passwd), passwd)
    s.send(sendData)
    resp = s.recv(1024)
    if resp != b'\x05\x00':
        print('auth failed, returned ' + binascii.b2a_hex(resp))
        return False
    ## 协商
    if mode == 3:
        s.send(b'\x05\x01\x00\x03' + struct.pack('B', 13) + b'www.sogou.com' + struct.pack('!H', 80))
        resp = s.recv(1024)
        if not resp[:2] == b'\x05\x00':
            print('socks connect to remote failed, returnd ' + binascii.b2a_hex(resp))
            return False
        ## 经过了协商，接下来就是正式发送数据了
        s.send(b'GET /web?query=ip&_asf=www.sogou.com&_ast=&w=01019900&p=40040100&ie=utf8&from=index-nologin&sut=393&sst0=1484636106444&lkt=2%2C1484636106052%2C1484636106155 HTTP/1.1\r\nHost:www.sogou.com\r\n\r\n')
        while 1:
            data = s.recv(2048)
            if data:
                print(data)
            else:
                break
        return True
    elif mode == 1:
        s.send(b'\x05\x01\x00\x01' + socket.inet_aton('47.88.190.46') + struct.pack('!H', 80))
        resp = s.recv(1024)
        if not resp[:2] == b'\x05\x00':
            print('socks connect to remote failed, returnd ' + binascii.b2a_hex(resp))
            return False
        ## 经过了协商，接下来就是正式发送数据了
        s.send(b'GET / HTTP/1.1\r\nHost:api.linkcel.com\r\n\r\n')
        while 1:
            data = s.recv(2048)
            if data:
                ## 不换行
                print data,
            else:
                break
        return True


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        uname = sys.argv[1]
        passwd = sys.argv[2]
        mode = int(sys.argv[3])
        if testAuth(uname, passwd, mode):
            print('test with auth, mode = %d succeed' % mode)
        else:
            print('test with auth, mode = %d failed' % mode)
    else:
        if testNoauth():
            print('test with no auth succeed')
        else:
            print('test with no auth failed')

