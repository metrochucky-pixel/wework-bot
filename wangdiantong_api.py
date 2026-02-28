#!/usr/bin/env python3
"""
旺店通API - 修复版（兼容 daily_sales_report.py 的签名算法）
"""
import hashlib
import json
import time
import requests

def md5(str):
    m = hashlib.md5()
    m.update(str.encode("utf8"))
    return m.digest()

def byte2hex(list1):
    sign = []
    for i in list1:
        a_bytes = '{:02X}'.format(i)
        sign.append(a_bytes)
    return ''.join(sign).lower()

class WdtAPI:
    def __init__(self, sid, appkey, appsecret, base_url="https://api.wangdian.cn/openapi2"):
        self.sid = sid
        self.appkey = appkey
        self.appsecret = appsecret
        self.base_url = base_url if base_url.endswith("/") else base_url + "/"
    
    def sign(self, params):
        """正确的签名算法"""
        keys = sorted(params.keys())
        query = ""
        for key in keys:
            if key == "sign":
                continue
            if len(query) > 0:
                query = query + ';'
            query = query + "{:02n}".format(len(key))
            query = query + '-'
            query = query + key
            query = query + ':'
            value = str(params[key])
            query = query + "{:04n}".format(len(value))
            query = query + '-'
            query = query + value
        query = query + self.appsecret
        return byte2hex(md5(query))
    
    def post(self, api, params):
        """发送请求"""
        params.update({
            "appkey": self.appkey,
            "sid": self.sid,
            "timestamp": str(int(time.time()))
        })
        params["sign"] = self.sign(params)
        url = self.base_url + api + ".php"
        return requests.post(url, params, timeout=30).json()
    
    def stock(self, spec_no, start_time=None, end_time=None):
        """库存查询"""
        p = {"spec_no": spec_no, "page_size": "100"}
        if start_time:
            p["start_time"] = start_time
        if end_time:
            p["end_time"] = end_time
        return self.post("stock_query", p)
    
    def goods(self, page_size="20"):
        """商品查询"""
        return self.post("goods", {"page_size": page_size})
    
    def trade(self, start_time, end_time, page_size="100"):
        """订单查询"""
        return self.post("trade_query", {
            "start_time": start_time,
            "end_time": end_time,
            "page_size": page_size
        })

if __name__ == '__main__':
    import os
    wdt = WdtAPI(
        os.getenv("WDT_SID", "wsds2"),
        os.getenv("WDT_APPKEY", "wsds2-ot"),
        os.getenv("WDT_SECRET", "")
    )
    
    # 测试
    print("测试库存查询...")
    result = wdt.stock("389")
    print(f"Code: {result.get('code')}")
    print(f"Message: {result.get('message', 'OK')}")
