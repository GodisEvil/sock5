#!python
#-*- coding: utf-8 -*-
'''
    为每个有代理的国家_运营商创建一个监听套接字，接受来自用户的访问
    为用户提供不经认证的 socks5 服务，实际上转发给代理服务器，使用认证的 socks5 进行转发
    认证用户名从 redis 中选取，来自相同ip的用户使用同一认证用户名；
    限制使用同一用户名的数量；

    用户通信过程如下：
    1.用户使用不认证的 socks5 连接，
    2.根据端口选取一个可用的代理地址；
    3.使用该代理和用户的套接字select
'''

import socket
import select
import struct
import redis
import time
import binascii
import threading
import logging

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s  %(levelname)s  %(filename)s  '
                           '[%(lineno)d]  thread: %(threadName)s  %(funcName)s  msg: %(message)s',
                    datefmt='[%Y-%m-%d %H:%M:%S]',
                    filename='./portmap.log',
                    filemode='ab+')
logger = logging.getLogger(__name__)

redisMobile = redis.StrictRedis(db=1)

## cnop: {sock: socket, port: intPort}
proxySock = {}
## userIP: [proxyAddr, userNumber]
userMap = {}

def scanProxy():
    uportStart = 10000
    while 1:
        logger.debug('scan proxy')
        ## 扫描 mccimsi，获取所有 cnop，记下所有有代理的 cnop
        cnops = redisMobile.hgetall('mccimsi')
        for imsi in cnops:
            cnop = cnops[imsi]
            if redisMobile.exists(cnop):
                if cnop not in proxySock:
                    ## 创建套接字
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    # sock.setblocking(False)
                    ## 绑定端口
                    sock.bind(('0.0.0.0', uportStart))
                    sock.listen(10)
                    proxySock[cnop] = {'sock': sock, 'port': uportStart}
                    redisMobile.hset('portmap', cnop, uportStart)
                    uportStart += 1
        time.sleep(5)


def acceptUser():
    '''
    使用 select 处理多个端口，来接受来自用户的连接；为每个用户使用单独的线程转发
    :return:
    '''
    while 1:
        startTime = time.time()
        socks = set()
        smap = {}
        for i in proxySock:
            sock = proxySock[i]['sock']
            socks.add(sock)
            smap[sock] = {'cnop': i, 'port': proxySock[i]['port']}
        if not socks:
            logger.info('no proxy so no socks')
            time.sleep(5)
            continue
        ws = set()
        logger.debug('restart accept')
        errHappen = False
        while errHappen or time.time() - startTime < 5:
            ## 超时时间10s
            readable, writeable, exceptional = select.select(socks, ws, socks, 10)
            for r in readable:
                ## 处理用户套接字
                us, uaddr = r.accept()
                lcnop = redisMobile.scard(smap[r]['cnop'])
                lport = redisMobile.hlen(smap[r]['port'])
                if lcnop*32 <= lport:
                    logger.info('%s proxy available, used %s, drop' % (str(lcnop), str(lport)))
                    us.close()
                    continue
                userIp = uaddr[0]
                ## 如果用户在线，那么就沿用之前的代理
                if userIp in userMap:
                    proxyAddr = userMap[userIp][0]
                    userMap[userIp][1] += 1
                else:
                    ## 要避免某个代理被反复使用
                    proxyAddr = redisMobile.srandmember(smap[r]['cnop'])
                    tmpUsedProxy = [userMap[i][0] for i in userMap]
                    if proxyAddr in tmpUsedProxy:
                        ## 代理已经被占用，那么拒绝服务
                        logger.info(str(proxyAddr) + ' is used')
                        us.close()
                        continue
                    userMap[userIp] = [proxyAddr, 1]
                ## 使用 proxyAddr
                logger.debug(str(uaddr) + ' use ' + str(proxyAddr))
                ## 记录到 redis 以便可以在别的地方查看当前的代理使用状态
                redisMobile.hset(smap[r]['port'], str(uaddr), proxyAddr)
                th = threading.Thread(target=socks5Trans, args=(us, uaddr, smap[r]['port'], proxyAddr))
                th.setDaemon(True)
                th.start()
            for e in exceptional:
                logger.warn('socket %s exception' % str(e))
                errHappen = True


def socks5Auth(sock, username, passwd, cdata):
    '''
    完成socks5的认证和协商过程，接下来只需要转发数据就可以了
    :param sock:
    :param username:
    :param passwd:
    :return:
    '''
    sock.send(b'\x05\x01\x02')
    resp = sock.recv(1024)
    if resp != b'\x05\x02':
        logger.info('method is not supported, returnd ' + binascii.b2a_hex(resp))
        return False
    ulen = len(username)
    sendData = b'\x05' + struct.pack('B%dsB%ds' % (ulen, len(passwd)), ulen, username, len(passwd), passwd)
    sock.send(sendData)
    resp = sock.recv(1024)
    if resp != b'\x05\x00':
        logger.info(username + ' auth failed, returned ' + binascii.b2a_hex(resp))
        return False
    ## 协商目的地
    sock.send(cdata)
    resp = sock.recv(1024)
    if not resp[:2] == b'\x05\x00':
        logger.info('socks connect to server failed, returnd ' + binascii.b2a_hex(resp))
        return False
    return True


def socks5Trans(userSock, userAddr, port, proxyAddr):
    '''
    完成不经认证的 socks5 之后，连接到控制服务器，使用 proxyAddr 进行认证
    :param userSock:
    :param userAddr:
    :return:
    '''
    thName = threading.currentThread()
    userIP = userAddr[0]
    connection = None
    try:
        data = userSock.recv(1024)
        if len(data) <= 0:
            raise socket.error('received no data')
        ver = ord(data[:1])
        if ver != 5:
            raise socket.error('socks ver is %d, not supported' % ver)
        lenMethods = ord(data[1:2])
        methods = data[2:2 + lenMethods]
        allMethods = struct.unpack(str(lenMethods) + 'B', methods)
        logger.debug('all methods: %s' % str(allMethods))
        if 0 in allMethods:
            ## 选择不认证
            userSock.send(b'\x05\x00')
            ## 接下来用户会发出协商目的地址的数据
            consultData = userSock.recv(1024)
            if not consultData:
                raise socket.error('received nothing from %s when consult' % str(userAddr))
            ## 接下来是协商目的地址，直接转发给代理控制就可以了
            ## 建立与代理控制服务器的连接并通过认证，把连接与当前连接对应起来，做一个普通的代理
            connection = socket.create_connection(('127.0.0.1', 9999), timeout=5)
            logger.debug('created connection with proxy-control-server')
            if not socks5Auth(connection, proxyAddr, '', consultData):
                logger.info('auth failed: ' + proxyAddr)
                userSock.close()
                return False
            endFlag = b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            if userSock.send(endFlag) < len(endFlag):
                raise socket.error('send endflag to user failed')
            ## 协商完成，直接在这两个套接字之间进行转发就可以了；使用 select 足够
            userSock.setblocking(False)
            connection.setblocking(False)
            logger.info('using proxy ' + str(proxyAddr))
            rs = set([userSock, connection])
            while 1:
                anyRead = False
                readable, writeable, exceptional = select.select(rs, set(), rs, 60)
                for r in readable:
                    anyRead = True
                    if r is userSock:
                        data = userSock.recv(2048)
                        # logger.debug('received from user: \n' + data)
                        if not data:
                            raise socket.error('user closed socket')
                        while data:
                            sendLen = connection.send(data)
                            data = data[sendLen:]
                    elif r is connection:
                        data = connection.recv(16384)
                        # logger.debug('received from proxy: \n' + data)
                        if not data:
                            raise socket.error('proxy-control-server closed socket')
                        while data:
                            sendLen = userSock.send(data)
                            data = data[sendLen:]
                for e in exceptional:
                    logger.warn('error happened: ' + str(e))
                    return False
                if not anyRead:
                    raise socket.error('select timeout and nothing to read')
        else:
            logger.warn('user donot use un-auth socks5')
            return False
    except Exception, e:
        logger.warning('%s: %s' % (str(userAddr), str(e)))
    finally:
        ## 释放资源
        userSock.close()
        if not connection is None:
            connection.close()
        userMap[userIP][1] -= 1
        if userMap[userIP][1] <= 0:
            userMap.pop(userIP, None)
        redisMobile.hdel(port, str(userAddr))
        logger.info(str(userAddr) + ' finished')


if __name__ == '__main__':
    th2 = threading.Thread(target=acceptUser)
    th2.setDaemon(True)
    th2.start()
    scanProxy()
