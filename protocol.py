#!python
#-*- coding: utf-8 -*-
'''
    解析头部及完成连接第一步
'''

import socket, struct
import mobile
import user
import threading
import select
import logging

logger = logging.getLogger(__name__)

## socks 的方法，分别是 \x80  \x81  \x82
METHOD_MOBILE = 128
METHOD_DATA = 129
METHOD_KEEPALIVE = 130
METHOD_USER = 2
METHOD_NOAUTH = 0
METHOD_UNSUPPORTED = -1


ATYPE_IP = 1
ATYPE_DOMAIN = 3


class ProtocoErr(Exception):
    '''
    协议出错了抛出这个异常
    '''
    ## 认证过程异常
    ERR_AUTH = 1
    ## 数据传输异常
    ERR_TRANS = 2

    def __init__(self, code=1, msg='protocol error'):
        self.code = code
        self.message = msg


def socksAuth(sock):
    '''
    所有套接字的第一步处理都是这里，认证通过了根据返回的 method 来判断本次连接是什么数据，是mobile则不用进一步处理
    是user则需要进一步完成 socks5 的协商过程

    认证，如果是私有协议，会调用 mobile.dealData 来处理数据；
    如果是用户名密码认证，调用 user.auth 并把username和password作为参数
    :param sock:
    :return:    返回认证方法，80表示私有，2表示用户名密码认证，0表示无认证，-1表示不支持
    '''
    if not isinstance(sock, socket.SocketType):
        raise ProtocoErr(ProtocoErr.ERR_AUTH, 'args is not socket')
    data = sock.recv(1024)
    if len(data) <= 0:
        raise ProtocoErr(ProtocoErr.ERR_AUTH, 'received no data')
    ver = ord(data[:1])
    if ver != 5:
        raise ProtocoErr(ProtocoErr.ERR_AUTH, 'socks ver is %d, not supported' % ver)
    lenMethods = ord(data[1:2])
    methods = data[2:2+lenMethods]
    allMethods = struct.unpack(str(lenMethods) + 'B', methods)
    logger.debug('all methods: %s' % str(allMethods))
    if METHOD_MOBILE in allMethods:
        logger.debug('rsv')
        sock.send(b'\x05\x80')
        reply = sock.recv(1024)
        if not reply:
            raise ProtocoErr(ProtocoErr.ERR_AUTH, 'auth-mobile response nothing')
        ver = ord(reply[:1])
        if ver != 5:
            raise ProtocoErr(ProtocoErr.ERR_AUTH, 'auth return ver %d' % ver)
        (dlen, ) = struct.unpack('!H', reply[1:3])
        if dlen + 3 > len(reply):
            raise ProtocoErr(ProtocoErr.ERR_AUTH, 'data len is %d, actually is [%s]' %
                             (dlen, reply[3:]))
        msg = reply[3:3+dlen]
        ## 记下 imsi 和 系统版本，表示注册成功
        if not mobile.dealData(sock, msg):
            raise ProtocoErr(ProtocoErr.ERR_AUTH, 'auth failed')
        return METHOD_MOBILE
    ## 优先选择认证的
    elif METHOD_USER in allMethods:
        logger.debug('auth')
        sock.send(b'\x05\x02')
        reply = sock.recv(1024)
        if not reply:
            raise ProtocoErr, 'auth break'
        ver = ord(reply[:1])
        if ver != 5:
            raise ProtocoErr, 'auth return ver %d' % ver
        ulen = ord(reply[1:2])
        uname = reply[2:2 + ulen]
        plen = ord(reply[2 + ulen:3 + ulen])
        passwd = reply[3 + ulen: 3 + ulen + plen]
        logger.debug('name = %s, passwd = %s' % (uname, passwd))
        if not user.auth(sock, uname, passwd):
            raise ProtocoErr(ProtocoErr.ERR_AUTH, 'auth failed')
        return METHOD_USER
    elif METHOD_NOAUTH in allMethods:
        logger.debug('no auth')
        ## 不支持认证的话，选择无认证的
        sock.send(b'\x05\x00')
        return METHOD_NOAUTH
    else:
        ## 没有可接受的协议
        logger.debug('No acceptable protocol')
        sock.send(b'\xFF')
        return METHOD_UNSUPPORTED


def consult(data):
    '''
    解析协商数据
    :param data:
    :param thName:
    :return:    协商是否成功；目的地址（ip|domain），端口；头部结束位置
    '''
    ver = ord(data[:1])
    if ver != 5:
        raise  ProtocoErr(ProtocoErr.ERR_TRANS, 'socks ver is %d, not supported' % (ver))
    cmd = ord(data[1:2])
    if cmd != 1:
        raise ProtocoErr(ProtocoErr.ERR_TRANS, 'socks cmd is %d, not supported' % (cmd))
    atyp = ord(data[3:4])
    endPos = 0
    ## ipv4
    if atyp == ATYPE_IP:
        dst = socket.inet_ntoa(data[4:8])
        (dport, ) = struct.unpack('!H', data[8:10])
        endPos = 10
    ## domain
    elif atyp == ATYPE_DOMAIN:
        dstLen = ord(data[4:5])
        if dstLen + 5 > len(data):
            raise ProtocoErr(ProtocoErr.ERR_TRANS, 'dstLen = %d, but data is %d, %s' %
                             (dstLen, len(data), data))
        dst = data[5:5+dstLen]
        (dport,) = struct.unpack('!H', data[5+dstLen:7+dstLen])
        endPos = 7+dstLen
    ## ipv6
    elif atyp == 4:
        raise ProtocoErr(ProtocoErr.ERR_TRANS, 'ipv6 is not supported now')
        # dst = data[4:20]
        # dport = data[20:22]
    else:
        raise ProtocoErr(ProtocoErr.ERR_TRANS, 'atyp = %d, unknown' % (atyp))
    return atyp, dst, dport, endPos


def dealNotauth(sock, remoteSock):
    '''
    处理未认证用户的 socks 转发
    :param sock:
    :param remoteSock:
    :return:
    '''
    sock.setblocking(False)
    remoteSock.setblocking(False)
    rs = set([sock, remoteSock])
    ws = set()
    logger.info('client: %s, remote: %s' % (str(sock.getpeername()), str(remoteSock.getpeername())))
    try:
        while 1:
            anyRead = False
            readable, writeable, exceptional = select.select(rs, ws, rs, 60)
            for s in readable:
                anyRead = True
                if s is sock:
                    data = s.recv(1024)
                    if data:
                        if remoteSock.send(data) <= 0:
                            raise socket.error(socket.EBADF, 'remote %s is closed' % str(remoteSock.getpeername()))
                    else:
                        raise socket.error(socket.EBADF, 'sock %s is closed' % str(sock.getpeername()))
                elif s is remoteSock:
                    data = s.recv(4096)
                    if data:
                        if sock.send(data) <= 0:
                            raise socket.error(socket.EBADF, 'sock %s is closed' % str(sock.getpeername()))
                    else:
                        raise socket.error(socket.EBADF, 'remote %s is closed' % str(remoteSock.getpeername()))
                else:
                    raise socket.error('impossible, readable socket is %s' % (str(s.getpeername())))
                logger.debug('read [%s] from %s' % (data, str(s.getpeername())))
            for w in writeable:
                raise socket.error('impossible, no writeable socket')
            for i in exceptional:
                raise socket.error('exceptional for %s' % i.getpeername())
            if not anyRead:
                raise socket.error('select timeout and nothing to read')
    except socket.error, e:
        ## 如果某个套接字关闭了，select 抛出异常 EBADF
        if e.errno == socket.EBADF:
            logger.info('some socket closed')
            return True
    finally:
        remoteSock.close()
        sock.close()
        logger.info('completed')
    return False


def createRsvHead(cmd, rsv, atyp, dst, dport):
    '''
    构造私有数据包的头部
    :param atyp:
    :param dst:
    :param dport:
    :return:
    '''
    prefix = struct.pack('BBBB', 5, cmd,  rsv, atyp)
    if atyp == 1:
        dst = socket.inet_aton(dst)
    elif atyp == 3:
        dst = struct.pack('B%ds' % len(dst), len(dst), dst)
    else:
        logger.error('atyp = %s is not supported' % str(atyp))
        return b''
    head = prefix + dst + struct.pack('!H', dport)
    return head


def dealUser(sock, remoteSock, header):
    '''
    认证用户的 socks 转发直接单线程阻塞监听，如果收到数据就转发给代理；代理收到数据会在另一个单独的线程里转发给用户
    :param sock:
    :param remoteSock:
    :param header:
    :return:
    '''
    try:
        sock.setblocking(False)
        rs = set([sock])
        while 1:
            anyRead = False
            readable, writeable, exceptional = select.select(rs, set(), set(), 60)
            for r in readable:
                anyRead = True
                if r is sock:
                    data = sock.recv(1024)
                    if data:
                        logger.debug('send data len %d to proxy' % len(data))
                        dlen = struct.pack('!H', len(data))
                        sendData = header + dlen + data
                        if not mobile.sendData(remoteSock, sendData):
                            logger.info('proxy %s sendData failed' % str(remoteSock.getpeername()))
                            return False
                    else:
                        raise socket.error('it should blocked but return with 0 byte')
                # elif r is remoteSock:
                #     key = mobile.MOBILE_KEYS[remoteSock.fileno()]
                #     try:
                #         data = r.recv(4096)
                #         if len(data) <= 0:
                #             raise socket.error('received 0 byte')
                #     except socket.error, e:
                #         logger.info('proxy %s is down: %s' % (key, str(e)))
                #         mobile.downSock(r)
                #         continue
                #     logger.debug('received %d from %s' % (len(data), key))
                #     if mobile.MOBILE_CLIENTS[key]['remain'] != '':
                #         data = mobile.MOBILE_CLIENTS[key]['remain'] + data
                #         mobile.MOBILE_CLIENTS[key]['remain'] = ''
                #     while len(data) > 0:
                #         ## 头部不完整那么不继续，直接保留
                #         if len(data) <= 6:
                #             mobile.MOBILE_CLIENTS[key]['remain'] = data
                #             logger.warn('data len < 6: %s' % data)
                #             break
                #         cmd = ord(data[1:2])
                #         rsv = ord(data[2:3])
                #         status = ord(data[3:4])
                #         (dlen,) = struct.unpack('!H', data[4:6])
                #         allLen = len(data)
                #         ## 本包还有部分数据没收到，那么记下就可以了
                #         if allLen < 6 + dlen:
                #             mobile.MOBILE_CLIENTS[key]['remain'] = data
                #             logger.info('remain some data because allLen = %d, dlen = %d' % (allLen, dlen))
                #             break
                #         rdata = data[6:6 + dlen]
                #         logger.debug('after deal, from proxy: cmd = %d, rsv = %d, status = %d, dlen = %d, allLen = %d' %
                #                      (cmd, rsv, status, dlen, allLen))
                #         if status != 0:
                #             userSock = mobile.getSockOfRsv(key, rsv)
                #             logger.error('proxy %s rejected rsv = %d, socket %s' % (key, rsv, str(userSock)))
                #             user.downUser(userSock)
                #         elif cmd == METHOD_DATA:
                #             userSock = mobile.getSockOfRsv(key, rsv)
                #             if userSock:
                #                 try:
                #                     sendLen = userSock.send(rdata)
                #                     if sendLen <= 0:
                #                         raise socket.error('send to user failed')
                #                     elif sendLen < dlen:
                #                         ## 一次发送没有发送完
                #                         logger.warn('send %d < dataLen %d' % (sendLen, dlen))
                #                     else:
                #                         logger.debug('send %d' % sendLen)
                #                 except socket.error, e:
                #                     ## 用户断开了连接，那么不能保留任何数据以免污染后来的连接
                #                     mobile.MOBILE_CLIENTS[key]['remain'] = ''
                #                     user.downUser(userSock)
                #         else:
                #             logger.error('proxy %s send cmd = %d' % (key, cmd))
                #             mobile.downSock(r)
                #             break
                #         data = data[6 + dlen:]
            for w in writeable:
                raise socket.error('impossible, no writeable socket')
            for i in exceptional:
                raise socket.error('exceptional for %s' % str(i))
            if not anyRead:
                raise socket.error('select timeout and nothing to read')
    except Exception, e:
        if isinstance(e, socket.error):
            logger.debug('user socket closed: ' + str(e))
        else:
            logger.exception('*** error: e' % str(e))
    finally:
        user.downUser(sock)
    return True


def handleSock(sock):
    '''
    处理 socket5 ，包括验证功能
    :param sockFd:
    :return:
    '''
    th = threading.currentThread()
    thName = th.getName()
    peerIp = str(sock.getpeername())
    logger.info('start thread: %s' % thName)
    if not isinstance(sock, socket.SocketType):
        logger.warn('*** %s: args is not socket, quit' % thName)
        return False
    try:
        authMethod = socksAuth(sock)
    except (ProtocoErr,socket.error), e:
        logger.info('*** %s, %s: %s' % (thName, peerIp, e.message))
        sock.close()
        return False
    ## 认证未通过
    if authMethod == -1:
        sock.close()
        return True
    ## 如果是手机端，认证后已经记录到全局变量了，由 keepalive 来处理存活
    if authMethod == METHOD_MOBILE:
        sock.setblocking(False)
        logger.info('proxy %s up' % str(sock.getpeername()))
        return True
    ## 否则表示是用户，需要进一步协商，获取到对端地址
    try:
        data = sock.recv(1024)
        if not data:
            raise ProtocoErr(ProtocoErr.ERR_TRANS,'peer %s closed' % str(sock.getpeername()))
        atyp, dst, dport, endPos = consult(data)
        ## 建立连接
        if authMethod == METHOD_NOAUTH:
            logger.info('no auth %s up' % str(sock.getpeername()))

            ## TODO 测试代码，稍后删除
            # remoteSock, rsv = mobile.getClient('', sock)
            # if not remoteSock is None:
            #     logger.info('use proxy %s, rsv %s' % (str(remoteSock), str(rsv)))
            #     header = createRsvHead(cmd=METHOD_DATA, rsv=rsv, atyp=atyp, dst=dst, dport=dport)
            #     if sock.send(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00') <= 0:
            #         raise ProtocoErr(ProtocoErr.ERR_TRANS, 'peer %s closed' % str(sock.getpeername()))
            #     return dealUser(sock, remoteSock, header)

            remoteSock = socket.create_connection((dst, dport), 60)
            ## 通知客户端连接成功
            if sock.send(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00') <= 0:
                raise ProtocoErr(ProtocoErr.ERR_TRANS, 'peer %s closed' % str(sock.getpeername()))
            return dealNotauth(sock, remoteSock)
        elif authMethod == METHOD_USER:
            logger.info('user %s up' % str(sock.getpeername()))
            remoteSock = user.getProxy(sock)
            rsv = user.getRsv(sock)
            if not remoteSock or rsv == -1:
                raise ProtocoErr(ProtocoErr.ERR_TRANS, 'remote sock %s, rsv is %s' %
                                          (str(remoteSock.getpeername()), str(rsv)))
            ## 通知客户端连接成功
            if sock.send(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00') <= 0:
                raise ProtocoErr(ProtocoErr.ERR_TRANS, 'peer %s closed' % str(sock.getpeername()))
            ## 到手机端注册代理地址；会在 watchProxy 里检测协商是否成功
            header = createRsvHead(cmd=METHOD_DATA, rsv=rsv, atyp=atyp, dst=dst, dport=dport)
            if not header:
                raise ValueError, 'create header failed'
        else:
            raise ProtocoErr(ProtocoErr.ERR_TRANS,'method is %s' % str(authMethod))
    except Exception, e1:
        logger.exception(peerIp + ',' + str(e1))
        user.downUser(sock)
        return False
    return dealUser(sock, remoteSock, header)
