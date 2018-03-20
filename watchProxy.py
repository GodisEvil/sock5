#!python
#-*- coding: utf-8 -*-
'''
    尽量使用 epoll，如果不存在则使用 select；
'''

import time, logging
import mobile, user, protocol
import select
import socket
import struct

logger = logging.getLogger(__name__)


if not hasattr(select, 'epoll'):
    def watchProxy():
        '''
        用 select 监视代理，可读时读取数据并根据 rsv 写入用户的套接字；
        最迟 10 s 会扫描一遍可用的代理
        :return:
        '''
        while 1:
            startTime = time.mktime(time.gmtime())
            proxySocks = set([mobile.MOBILE_CLIENTS[i]['sock'] for i in mobile.MOBILE_CLIENTS])
            if not proxySocks:
                time.sleep(1)
                logger.debug('no proxy online, restart watch...')
                continue
            logger.debug('restart watch...')
            ws = set([])
            ## 如果 select 5s 内返回了，不重复读取代理集；如果有代理挂掉了，当然要重新判断
            proxyDown = False
            while not proxyDown and time.mktime(time.gmtime()) - startTime < 5:
                readable, writeable, exceptional = select.select(proxySocks, ws, proxySocks, 10)
                for r in readable:
                    key = mobile.getKey(r)
                    r = mobile.MOBILE_CLIENTS[key]['sock']
                    try:
                        data = r.recv(16384)
                        if len(data) <= 0:
                            raise socket.error('received 0 byte')
                    except socket.error, e:
                        logger.info('proxy %s is down: %s' % (key, str(e)))
                        mobile.downSock(r)
                        proxyDown = True
                        continue
                    logger.debug('received %d from %s' % (len(data), key))
                    if mobile.MOBILE_CLIENTS[key]['remain'] != '':
                        data = mobile.MOBILE_CLIENTS[key]['remain'] + data
                        mobile.MOBILE_CLIENTS[key]['remain'] = ''
                    ## userSock: data
                    sendData = {}
                    while len(data) > 0:
                        ## 头部不完整那么不继续，直接保留
                        if len(data) <= 6:
                            mobile.MOBILE_CLIENTS[key]['remain'] = data
                            logger.warn('data len < 6: %s' % data)
                            break
                        cmd = ord(data[1:2])
                        rsv = ord(data[2:3])
                        status = ord(data[3:4])
                        (dlen,) = struct.unpack('!H', data[4:6])
                        allLen = len(data)
                        ## 本包还有部分数据没收到，那么记下就可以了；但是如果用户已经关闭了连接，那么直接丢掉数据
                        userSock = mobile.getSockOfRsv(key, rsv)
                        if not userSock:
                            logger.warn('key = %s, rsv = %d, user is not existed, continue' % (key, rsv))
                            break
                        if allLen < 6 + dlen:
                            mobile.MOBILE_CLIENTS[key]['remain'] = data
                            logger.info('remain some data because allLen = %d, dlen = %d' % (allLen, dlen))
                            break
                        rdata = data[6:6 + dlen]
                        logger.debug('after deal, from proxy: cmd = %d, rsv = %d, status = %d, dlen = %d, allLen = %d' %
                                     (cmd, rsv, status, dlen, allLen))
                        if status != 0:
                            logger.error('proxy %s rejected rsv = %d, socket %s' % (key, rsv, str(userSock)))
                            user.downUser(userSock)
                        elif cmd == protocol.METHOD_DATA:
                            if userSock in sendData:
                                sendData[userSock] += rdata
                            else:
                                sendData[userSock] = rdata
                        else:
                            logger.error('proxy %s send cmd = %d' % (key, cmd))
                            mobile.downSock(r)
                            proxyDown = True
                            break
                        data = data[6 + dlen:]
                    ## 发送数据
                    for uS in sendData:
                        sdata = sendData[uS]
                        while len(sdata) > 0:
                            try:
                                slen = len(sdata)
                                sendLen = uS.send(sdata)
                                if sendLen < 0:
                                    raise socket.error('send to user failed')
                                elif sendLen <= slen:
                                    ## 一次发送没有发送完
                                    logger.info('send %d, dataLen %d' % (sendLen, slen))
                                    sdata = sdata[sendLen:]
                            except socket.error, e:
                                ## 用户断开了连接，那么这个用户的数据就不用处理了
                                logger.info('user down because: ' + str(e))
                                user.downUser(uS)
                                break
                for w in writeable:
                    logger.error('impossible, no write socket seleted: %s' % mobile.MOBILE_KEYS[w])
                for e in exceptional:
                    logger.warn('proxy %s down because of select exception' % mobile.MOBILE_KEYS[e])
                    mobile.downSock(e)
                    proxyDown = True

else:
    def watchProxy():
        '''
        用 select 监视代理，可读时读取数据并根据 rsv 写入用户的套接字；
        最迟 10 s 会扫描一遍可用的代理
        :return:
        '''
        while 1:
            startTime = time.mktime(time.gmtime())
            epollFd = select.epoll()
            ## 注册代理到 epoll
            for sockFileno in mobile.MOBILE_KEYS:
                epollFd.register(sockFileno, select.EPOLLIN | select.EPOLLET)
            if not epollFd:
                time.sleep(1)
                logger.debug('no proxy online, restart watch...')
                continue
            logger.debug('restart watch...')
            proxyDown = False
            ## 如果 epoll 快速返回了，5s内不重新扫描
            while not proxyDown and time.mktime(time.gmtime()) - startTime < 5:
                epollList = epollFd.poll(10)
                for fd, event in epollList:
                    if select.EPOLLIN & event:
                        key = mobile.MOBILE_KEYS[fd]
                        r = mobile.MOBILE_CLIENTS[key]['sock']
                        try:
                            data = r.recv(16384)
                            if len(data) <= 0:
                                raise socket.error('received 0 byte')
                        except socket.error, e:
                            logger.info('proxy %s is down: %s' % (key, str(e)))
                            mobile.downSock(r)
                            proxyDown = True
                            continue
                        logger.debug('received %d from %s' % (len(data), key))
                        if mobile.MOBILE_CLIENTS[key]['remain'] != '':
                            data = mobile.MOBILE_CLIENTS[key]['remain'] + data
                            mobile.MOBILE_CLIENTS[key]['remain'] = ''
                        ## userSock: data
                        sendData = {}
                        while len(data) > 0:
                            ## 头部不完整那么不继续，直接保留
                            if len(data) <= 6:
                                mobile.MOBILE_CLIENTS[key]['remain'] = data
                                logger.warn('data len < 6: %s' % data)
                                break
                            cmd = ord(data[1:2])
                            rsv = ord(data[2:3])
                            status = ord(data[3:4])
                            (dlen, ) = struct.unpack('!H', data[4:6])
                            allLen = len(data)
                            ## 本包还有部分数据没收到，那么记下就可以了；但是如果用户已经关闭了连接，那么直接丢掉数据
                            userSock = mobile.getSockOfRsv(key, rsv)
                            if not userSock:
                                logger.warn('key = %s, rsv = %d, user is not existed, continue' % (key, rsv))
                                break
                            if allLen < 6+dlen:
                                mobile.MOBILE_CLIENTS[key]['remain'] = data
                                logger.info('remain some data because allLen = %d, dlen = %d' % (allLen, dlen))
                                break
                            rdata = data[6:6 + dlen]
                            logger.debug('after deal, from proxy: cmd = %d, rsv = %d, status = %d, dlen = %d, allLen = %d' %
                                         (cmd, rsv, status, dlen, allLen))
                            if status != 0:
                                logger.error('proxy %s rejected rsv = %d, socket %s' % (key, rsv, str(userSock)))
                                user.downUser(userSock)
                            elif cmd == protocol.METHOD_DATA:
                                if userSock in sendData:
                                    sendData[userSock] += rdata
                                else:
                                    sendData[userSock] = rdata
                            else:
                                logger.error('proxy %s send cmd = %d' % (key, cmd))
                                mobile.downSock(r)
                                proxyDown = True
                                break
                            data = data[6+dlen:]
                        ## 发送数据
                        for uS in sendData:
                            sdata = sendData[uS]
                            while len(sdata) > 0:
                                try:
                                    slen = len(sdata)
                                    sendLen = uS.send(sdata)
                                    if sendLen < 0:
                                        raise socket.error('send to user failed')
                                    elif sendLen <= slen:
                                        ## 一次发送没有发送完
                                        logger.info('send %d, dataLen %d' % (sendLen, slen))
                                        sdata = sdata[sendLen:]
                                except socket.error, e:
                                    ## 用户断开了连接，那么这个用户的数据就不用处理了
                                    logger.info('user down because: ' + str(e))
                                    user.downUser(uS)
                                    break
                    elif event & select.EPOLLHUP:
                        sock = mobile.MOBILE_KEYS[fd]
                        mobile.downSock(sock)
                        proxyDown = True
                        logger.warn('proxy down when epoll, hup')
                    else:
                        logger.error('proxy epoll: %s for %s' % (str(event), str(fd)))
                        sock = mobile.MOBILE_KEYS[fd]
                        mobile.downSock(sock)
                        proxyDown = True
