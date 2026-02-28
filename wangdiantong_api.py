#!/usr/bin/env python3
"""
旺店通API - 极简版
直接用，无需额外依赖
"""
import hashlib
import json
import time
import requests

class WdtAPI:
    def __init__(self, sid, appkey, appsecret):
        self.sid = sid
        self.appkey = appkey
        self.appsecret = appsecret
        self.base = "https://api.wangdian.cn/openapi2"
    
    def sign(self, params):
        """签名算法"""
        keys = sorted(params.keys())
        query = ""
        for key in keys:
            if key == "sign": continue
            if query: query += ";"
            query += f"{len(key):02d}-{key}:{len(str(params[key])):04d}-{params[key]}"
        query += self.appsecret
        return hashlib.md5(query.encode()).hexdigest().lower()
    
    def post(self, api, params):
        """发送请求"""
        params.update({
            "appkey": self.appkey,
            "sid": self.sid,
            "timestamp": str(int(time.time()))
        })
        params["sign"] = self.sign(params)
        return requests.post(f"{self.base}/{api}.php", params).json()
    
    # ========== 常用接口 ==========
    
    def shop(self):
        """店铺列表"""
        return self.post("shop", {})
    
    def stock(self, spec_no, start_time=None, end_time=None):
        """库存查询 - spec_no填商品编码如BJD002"""
        p = {"spec_no": spec_no, "page_size": "100"}
        if start_time: p["start_time"] = start_time
        if end_time: p["end_time"] = end_time
        return self.post("stock_query", p)
    
    def sales(self, date, shop_no=None, spec_no=None):
        """销售统计 - date格式2026-02-06"""
        p = {"consign_date": date}
        if shop_no: p["shop_no"] = shop_no
        if spec_no: p["spec_no"] = spec_no
        return self.post("vip_stat_sales_by_spec_shop_warehouse_query", p)
    
    def purchase(self, start_time, end_time):
        """采购单查询"""
        return self.post("purchase_order_query", {
            "start_time": start_time,
            "end_time": end_time,
            "page_size": "50"
        })


# ========== 使用示例 ==========

if __name__ == "__main__":
    # 初始化（用你的凭证）
    api = WdtAPI(
        sid="wsds2",
        appkey="wsds2-ot",
        appsecret="5acff34ec2d0d1c028bbdd6b47c28c57"
    )
    
    # 1. 查店铺
    print("🏪 店铺列表:")
    r = api.shop()
    for s in r.get("shoplist", [])[:5]:
        print(f"   {s['shop_no']}: {s['shop_name']}")
    
    # 2. 查库存（BJD002百加得）
    print("\n📦 BJD002库存:")
    r = api.stock("BJD002")
    for item in r.get("stocks", [])[:3]:
        print(f"   {item['warehouse_name']}: {item['stock_num']}件 (成本{item['cost_price']})")
    
    # 3. 查昨日销售
    print("\n💰 昨日销售TOP:")
    from datetime import datetime, timedelta
    yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    r = api.sales(yesterday)
    items = sorted(r.get("stat_list", []), key=lambda x: float(x.get("amount", 0)), reverse=True)
    for i in items[:5]:
        print(f"   {i.get('shop_name', '未知店铺')}: {i['num']}件 ¥{float(i['amount']):,.0f}")
