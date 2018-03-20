#!python
#-*- coding: utf-8 -*-
'''
    用户端

    有一个单独的进程监听某个端口，
'''

import socket
import mobile
import logging

logger = logging.getLogger(__name__)

## userSocket: proxySocket
USER = {}

def auth(sock, uname, passwd):
    '''
    认证，如果是私有协议，会调用 dealData 来处理数据；
    如果是用户名密码认证，调用dealData并把username和password作为参数
    :param sock:
    :return:    返回认证方法，80表示私有，2表示用户名密码认证，0表示无认证，-1表示不支持
    '''
    if not isinstance(sock, socket.SocketType):
        logger.error('args is not socket')
        return False
    client, rsv = mobile.getClient(uname, sock)
    if not client:
        logger.warn('client %s is not available' % uname)
        return False
    try:
        if sock.send(b'\x05\x00') > 0:
            USER[sock] = {'proxy': client, 'rsv': rsv}
            return True
    except Exception, e:
        if isinstance(e, socket.error):
            logger.warn('client %s closed when auth' % str(sock))
        else:
            logger.warn('client %s auth failed: %s' % (str(sock), str(e)))
        ## 释放proxy
        mobile.releaseClient(mobile.getKey(client), rsv)
        return False
    return False


def getProxy(sock):
    if sock in USER:
        return USER[sock]['proxy']
    return None


def releaseProxy(sock):
    proxySock = getProxy(sock)
    if isinstance(proxySock, socket.SocketType):
        rsv = getRsv(sock)
        key = mobile.getKey(proxySock)
        if key:
            mobile.releaseClient(key, rsv)


def isUserOnline(sock):
    return sock in USER


def downUser(sock):
    logger.info('user down...')
    if isinstance(sock, socket.SocketType):
        sock.close()
    releaseProxy(sock)
    USER.pop(sock, None)


def getRsv(sock):
    if sock in USER:
        return USER[sock]['rsv']
    return -1
