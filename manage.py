#!python
#-*- coding: utf-8 -*-
'''
    管理，提供接口用于展示当前可用代理
'''

from gevent import monkey
monkey.patch_all()

from gevent.pywsgi import WSGIServer
import json
from flask import Flask
import redis

app = Flask(__name__)
rcli = redis.StrictRedis(db=1)

@app.route('/proxy/show')
def show():
    result = {}
    cnops = rcli.hgetall('portmap')
    for cnop in cnops:
        proxySum = rcli.scard(cnop)
        proxyUsed = rcli.hlen(cnops[cnop]) % 32
        available = proxySum-proxyUsed
        result[cnop] = {'port': cnops[cnop], 'sum': proxySum, 'available': available if available >= 0 else 0, 'used': proxyUsed}
    return json.dumps({'code': 0, 'data': result}, ensure_ascii=False)


if __name__ == '__main__':
    app.debug = True
    httpServer = WSGIServer(('0.0.0.0', 9998), app)
    httpServer.serve_forever()
