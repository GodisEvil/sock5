#!python
#-*- coding: utf-8 -*-
'''
    处理手机端的连接，连接之后要记录到一个 list|dict 中，包括了该连接的创建时间，最近通信时间，地址（ip:port），
    做一个转换，以 sock：ip:port ，再以 'ip:port': '' 存储详情
    这样就可以定时检查状态以及做其他管理操作

    把可用代理存储到 redis，按照 ip:port:{'imsi':xx, 'sysver':xx} 的方式存储，另以 proxy: [ip:port] 来查询
'''
import logging
import json
import time
import redis


logger = logging.getLogger(__name__)

## {'ctime': time, 'uptime': time, 'sock': sock}
MOBILE_CLIENTS = {}
MOBILE_KEYS = {}
MOBILE_SOCKS = {}
redisMobile = redis.StrictRedis(db=1)


def initIsp():
    '''初始化 imsi 与 country  isp 对应关系'''
    import mysql.connector
    from mysql.connector.cursor import MySQLCursorBuffered
    mysqlConfig = {'host': '58.96.169.105', 'user': 'ifb', 'password': 'abcd1234',
                   'port': 3306, 'database': 'db_sp', 'charset': 'utf8', 'autocommit': 0
                   # ,'pool_name': 'mypool', 'pool_size': MYSQL_POOL_SIZE
                   }
    con = mysql.connector.Connect(**mysqlConfig)
    cur = con.cursor(cursor_class=MySQLCursorBuffered)
    sql = 'select mcccode,isp,domainName from mccimsi'
    cur.execute(sql)
    if not cur or cur.rowcount <= 0:
        logger.error('initIsp failed')
        return False
    ret = cur.fetchall()
    for i in ret:
        redisMobile.hset('mccimsi', i[0], i[2] + '_' + i[1])
    cur.close()
    con.close()
    return True


def getKey(sock):
    '''
    使用 sock 的 remote_ip: remote_port 作为key的好处是即使某个套接字关闭了又重新打开，可以立即重用
    另外用户认证的时候直接作为用户名
    :param sock:
    :return:
    '''
    fd = MOBILE_SOCKS.get(sock, -1)
    return MOBILE_KEYS.get(fd, '')


def mobileUp(address, info):
    imsi = info.get('imsi', '')
    key = redisMobile.hget('mccimsi', imsi[:5])
    if not key:
        key = redisMobile.hget('mccimsi', imsi[:6])
    if not key:
        key = 'unknown'
    redisMobile.sadd(key, address)
    return key


def mobileDown(cnop, address):
    redisMobile.srem(cnop, address)


def dealData(sock, data):
    '''
    处理私有协议的数据，会是一个json结构，包括 imsi，sysver
    :param sock:
    :type   socket.SocketType
    :param data:
    :return:
    '''
    try:
        jd = json.loads(data)
    except json.JSONEncoder, e:
        logger.warn('data is not json: %s' % data)
        return False
    ## 拒绝 imsi 为空的代理
    if 'imsi' not in jd or 'apn_name' not in jd or not 'ver' in jd or not jd['imsi']:
        logger.warn('data is not correct: %s' % data)
        return False
    ##  记下imsi和sysver，认证通过；同时要通过 imsi 来判断是否接受连接，如果某个运营商已经满了就不再继续
    logger.debug(str(jd))
    host, port = sock.getpeername()
    if sock.send(b'\x05\x00') > 0:
        clientKey = str(host) + ':' + str(port)
        if not clientKey:
            logger.warn('no... proxy closed just after auth')
            return False
        if clientKey in MOBILE_CLIENTS:
            logger.warn('%s existed' % clientKey)
            return False
        now = time.mktime(time.gmtime())
        MOBILE_SOCKS[sock] = sock.fileno()
        MOBILE_KEYS[MOBILE_SOCKS[sock]] = clientKey
        MOBILE_CLIENTS[clientKey] = {'ctime': now, 'uptime': now, 'sock': sock, 'peer': {}, 'imsi': jd['imsi'], 'remain': ''}
        cnOp = mobileUp(clientKey, jd)
        MOBILE_CLIENTS[clientKey]['cnop'] = cnOp
        return True
    else:
        logger.info('send confirm failed')
        raise False

import threading

MUTEX = threading.Lock()
def getClient(key, userSock):
    MUTEX.acquire()
    if key == '' and MOBILE_CLIENTS:
        key = MOBILE_CLIENTS.keys()[0]
    ## 最多允许 32 个用户
    if key in MOBILE_CLIENTS:
        peerLen = len(MOBILE_CLIENTS[key]['peer'])
        if peerLen > 64:
            MUTEX.release()
            return None, -1
        usedRsv = set([pk for pk in MOBILE_CLIENTS[key]['peer']])
        ## 分配一个不属于 usedRsv 的 rsv 给用户
        for i in range(0, peerLen + 1, 1):
            if i not in usedRsv:
                MOBILE_CLIENTS[key]['peer'][i] = userSock
                MUTEX.release()
                return MOBILE_CLIENTS[key]['sock'], i
    MUTEX.release()
    return None, -1


def releaseClient(key, rsv):
    if key in MOBILE_CLIENTS:
        MOBILE_CLIENTS[key]['peer'].pop(rsv, '')


def downSock(sock):
    ## 代理下线；但是可能用户还没下线，主动关闭掉所有用户
    key = getKey(sock)
    fd = MOBILE_SOCKS[sock]
    logger.info('proxy %s down...' % key)
    clientKey = MOBILE_KEYS[fd]
    MOBILE_KEYS.pop(fd, None)
    sock.close()
    for rsv in MOBILE_CLIENTS[clientKey]['peer']:
        usock = MOBILE_CLIENTS[clientKey]['peer'][rsv]
        usock.close()
    mobileDown(MOBILE_CLIENTS[clientKey]['cnop'], clientKey)
    MOBILE_CLIENTS.pop(clientKey, None)
    MOBILE_SOCKS.pop(sock, None)


def sendData(sock, data):
    '''
    发送数据到远端，key 是远端的 key
    :param data:
    :return:
    '''
    fd = sock.fileno()
    clientKey = MOBILE_KEYS[fd]
    if clientKey not in MOBILE_CLIENTS:
        raise ValueError, 'key = %s is not connected' % clientKey
    while data:
        sendLen = sock.send(data)
        if sendLen < 0:
            downSock(sock)
            return False
        elif sendLen <= len(data):
            MOBILE_CLIENTS[clientKey]['uptime'] = time.mktime(time.gmtime())
            data = data[sendLen:]
            continue
    return True


def getSockOfRsv(key, rsv):
    if key in MOBILE_CLIENTS:
        return MOBILE_CLIENTS[key]['peer'].get(rsv, None)
    return None


def touch(sock):
    clientKey = getKey(sock)
    if clientKey not in MOBILE_CLIENTS:
        MOBILE_CLIENTS[clientKey]['uptime'] = time.mktime(time.gmtime())

