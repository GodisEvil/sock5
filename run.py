#!python
#-*- coding: utf-8 -*-
'''
    入口
'''

import sys
reload(sys)
sys.setdefaultencoding('utf-8')
import socket
import threading
import protocol
import user
import logging
import struct
import mobile
import time
import watchProxy

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s  %(levelname)s  %(filename)s  '
                           '[%(lineno)d]  thread: %(threadName)s  %(funcName)s  msg: %(message)s',
                    datefmt='[%Y-%m-%d %H:%M:%S]',
                    filename='./socks5.log',
                    filemode='ab+')
logger = logging.getLogger(__name__)


def keepalive():
    '''
    遍历 MOBILE_CLIENTS，发送心跳包
    :return:
    '''
    while 1:
        keys = mobile.MOBILE_CLIENTS.keys()
        if not keys:
            logger.debug('no proxy')
        else:
            for key in keys:
                ## 检查对端是否在线
                rsvs = mobile.MOBILE_CLIENTS[key]['peer'].keys()
                for rsv in rsvs:
                    peer = mobile.MOBILE_CLIENTS[key]['peer'][rsv]
                    if not user.isUserOnline(peer):
                        logger.error('peer %s is not online' % str(peer))
                        mobile.MOBILE_CLIENTS[key]['peer'].pop(rsv)

                sock = mobile.MOBILE_CLIENTS[key]['sock']
                now = time.mktime(time.gmtime())
                ## 对于超过了30s未发送或接收数据的套接字，需要发送心跳包
                if now - int(mobile.MOBILE_CLIENTS[key]['uptime']) >= 30:
                    sendLen = -1
                    try:
                        sendLen = sock.send(struct.pack('BB', 5, protocol.METHOD_KEEPALIVE))
                    except socket.error, e:
                        if e.errno == socket.EBADF:
                            pass
                    if sendLen > 0:
                        ## 要是对端网速不好可能延迟较长，所以重新取时间
                        mobile.MOBILE_CLIENTS[key]['uptime'] = time.mktime(time.gmtime())
                        logger.debug('sock %s is alive' % str(sock.getpeername()))
                    else:
                        logger.info('%s down' % key)
                        mobile.downSock(sock)
        time.sleep(3)


def main():
    mobile.initIsp()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 9999))
    ## 首先启动手机代理的检查线程
    th = threading.Thread(target=keepalive)
    th.setDaemon(True)
    th.start()
    th = threading.Thread(target=watchProxy.watchProxy)
    th.setDaemon(True)
    th.start()
    sock.listen(10)
    while 1:
        conn, addr = sock.accept()
        # conn.settimeout(60)
        ## 超时时间60s
        t = threading.Thread(target=protocol.handleSock, args=(conn,))
        t.setDaemon(True)
        t.start()


if __name__ == '__main__':
    main()
