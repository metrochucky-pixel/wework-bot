#!/usr/bin/env python3
"""
企业微信消息接收服务
处理用户发来的消息，调用 AI 回复
"""
import json
import os
import sys
import hashlib
import base64
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import parse_qs
from Crypto.Cipher import AES
import requests

sys.path.insert(0, '/Users/chuck/.openclaw/workspace')
sys.path.insert(0, '/opt/wework-bot')

# 导入旺店通 API
try:
    from wangdiantong_api import WdtAPI
    # 从 keychain 或环境变量获取密钥
    import os
    WDT_SID = os.getenv('WDT_SID', '')
    WDT_APPKEY = os.getenv('WDT_APPKEY', '')
    WDT_APPSECRET = os.getenv('WDT_APPSECRET', '')
    wdt_api = WdtAPI(WDT_SID, WDT_APPKEY, WDT_APPSECRET) if WDT_SID else None
except Exception as e:
    print(f"⚠️ 旺店通 API 加载失败: {e}")
    wdt_api = None

# 企业微信配置
CORP_ID = "ww1b7a366e3b44c277"
AGENT_ID = "1000018"
CALLBACK_TOKEN = "OJEmMp1mLtO5hGQe"
ENCODING_AES_KEY = "NEDLcWJ4tegNMISoRHrZ6iD5UmFnXPaGJvBs4IM2vlE"

class WeWorkCallback:
    """企业微信回调处理"""
    
    def __init__(self):
        self.token = CALLBACK_TOKEN
        self.aes_key = base64.b64decode(ENCODING_AES_KEY + "=")
        self.corp_id = CORP_ID
    
    def verify_url(self, signature, timestamp, nonce, echostr):
        """
        验证 URL（企业微信配置时调用）
        按字典序排序 token, timestamp, nonce, echostr，SHA1 签名
        """
        sort_list = sorted([self.token, timestamp, nonce, echostr])
        sort_str = ''.join(sort_list)
        
        sha1 = hashlib.sha1()
        sha1.update(sort_str.encode())
        calc_signature = sha1.hexdigest()
        
        if calc_signature == signature:
            # 验证通过，返回 echostr
            return echostr
        else:
            print(f"❌ 签名验证失败: {calc_signature} != {signature}")
            return None
    
    def decrypt_msg(self, encrypt_msg):
        """
        解密企业微信消息
        使用 AES-CBC 解密
        """
        try:
            # Base64 解码
            encrypted = base64.b64decode(encrypt_msg)
            
            # AES 解密
            cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_key[:16])
            decrypted = cipher.decrypt(encrypted)
            
            # 去除填充
            pad = decrypted[-1]
            content = decrypted[:-pad]
            
            # 去掉前 16 个随机字节，后 4 个字节是 msg_len，然后是企业ID
            xml_len = int.from_bytes(content[16:20], 'big')
            xml_content = content[20:20+xml_len].decode('utf-8')
            
            return xml_content
        except Exception as e:
            print(f"❌ 解密失败: {e}")
            return None
    
    def encrypt_msg(self, xml_msg, nonce, timestamp):
        """
        加密回复消息
        """
        try:
            # 随机 16 字节 + xml 长度(4字节) + xml + corp_id
            random_bytes = os.urandom(16)
            msg_len = len(xml_msg.encode())
            msg_bytes = xml_msg.encode()
            corp_id_bytes = self.corp_id.encode()
            
            content = random_bytes + msg_len.to_bytes(4, 'big') + msg_bytes + corp_id_bytes
            
            # PKCS7 填充
            block_size = 32
            pad_len = block_size - (len(content) % block_size)
            content += bytes([pad_len] * pad_len)
            
            # AES 加密
            cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_key[:16])
            encrypted = cipher.encrypt(content)
            
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            print(f"❌ 加密失败: {e}")
            return None
    
    def generate_signature(self, timestamp, nonce, encrypt_msg):
        """生成消息签名"""
        sort_list = sorted([self.token, timestamp, nonce, encrypt_msg])
        sort_str = ''.join(sort_list)
        
        sha1 = hashlib.sha1()
        sha1.update(sort_str.encode())
        return sha1.hexdigest()


class WeWorkHandler:
    """处理企业微信消息"""
    
    def __init__(self):
        self.callback = WeWorkCallback()
    
    def handle_get(self, query_params):
        """处理 GET 请求（URL 验证）"""
        signature = query_params.get('msg_signature', [''])[0]
        timestamp = query_params.get('timestamp', [''])[0]
        nonce = query_params.get('nonce', [''])[0]
        echostr = query_params.get('echostr', [''])[0]
        
        print(f"🔍 URL 验证请求:")
        print(f"   signature: {signature}")
        print(f"   timestamp: {timestamp}")
        print(f"   nonce: {nonce}")
        print(f"   echostr: {echostr}")
        
        result = self.callback.verify_url(signature, timestamp, nonce, echostr)
        
        if result:
            print("✅ URL 验证通过")
            return result
        else:
            print("❌ URL 验证失败")
            return None
    
    def handle_post(self, query_params, xml_body):
        """处理 POST 请求（接收消息）"""
        signature = query_params.get('msg_signature', [''])[0]
        timestamp = query_params.get('timestamp', [''])[0]
        nonce = query_params.get('nonce', [''])[0]
        
        print(f"📩 收到消息:")
        print(f"   signature: {signature}")
        print(f"   timestamp: {timestamp}")
        print(f"   nonce: {nonce}")
        
        # 解析 XML
        try:
            root = ET.fromstring(xml_body)
            to_user = root.find('ToUserName').text
            encrypt = root.find('Encrypt').text
            
            # 解密消息
            decrypt_xml = self.callback.decrypt_msg(encrypt)
            if not decrypt_xml:
                return None
            
            print(f"📄 解密后 XML:\n{decrypt_xml}")
            
            # 解析消息内容
            msg_root = ET.fromstring(decrypt_xml)
            msg_type = msg_root.find('MsgType').text
            from_user = msg_root.find('FromUserName').text
            
            print(f"👤 来自: {from_user}")
            print(f"📌 类型: {msg_type}")
            
            # 处理不同类型的消息
            if msg_type == 'text':
                content = msg_root.find('Content').text
                print(f"💬 内容: {content}")
                
                # 调用 AI 回答
                reply = self.get_ai_reply(content)
                
                # 构建回复
                return self.build_reply(from_user, to_user, reply)
            
            elif msg_type == 'event':
                event = msg_root.find('Event').text
                print(f"🎯 事件: {event}")
                
                if event == 'subscribe':
                    return self.build_reply(from_user, to_user, "🦊 小白已上线！有什么可以帮你的？")
                
            else:
                print(f"⚠️ 未处理的消息类型: {msg_type}")
                return None
                
        except Exception as e:
            print(f"❌ 处理消息失败: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def get_ai_reply(self, user_msg):
        """调用 AI 获取回复"""
        import re
        
        # 简单关键词匹配
        responses = {
            "你好": "嘿！我是小白，有啥事儿直说，别客气。🦊",
            "帮助": "我能帮你查库存、看价格、分析数据。直接说需求！",
            "库存": "要查哪款？直接报名字，我帮你翻仓库。",
            "价格": "哪款酒？茅台、奔富还是其他的？",
            "茅台": "茅台今天价格... 等我查查（假装在看数据）",
            "在么": "在啊。干嘛？🦊",
            "你是谁": "小白，老羊的24小时助手。白天干活，晚上...也是干活。",
        }
        
        # 精确匹配
        if user_msg in responses:
            return responses[user_msg]
        
        # 库存查询 - 提取商品名（如"奔富 389"、"茅台 2023"）
        if "库存" in user_msg or "查" in user_msg or "多少" in user_msg:
            # 尝试提取商品名（去掉"库存"、"查"等词）
            clean_msg = user_msg.replace("库存", "").replace("查", "").replace("一下", "").replace("吗", "").strip()
            if clean_msg and len(clean_msg) > 1:
                return self.query_stock(clean_msg)
        
        # 如果直接发商品名（如"奔富 389"），也查库存
        if re.match(r'^[\u4e00-\u9fa5]+\s*\d+$', user_msg.strip()):
            return self.query_stock(user_msg.strip())
        
        # 关键词匹配
        if "价格" in user_msg or "多少钱" in user_msg:
            return "哪款？别让我猜。"
        elif "茅台" in user_msg:
            return "茅台... 最近价格波动挺大，具体哪款？"
        elif "在" in user_msg and len(user_msg) < 5:
            return "在。说事。"
        elif "谢谢" in user_msg:
            return "别谢，应该的。还有别的吗？"
        elif "哈哈" in user_msg or "嘻嘻" in user_msg:
            return "笑啥？有啥好事？"
        
        # 默认回复
        return f"收到: {user_msg}\n\n这个我还不太会，去问老羊吧，或者等我学一学。🦊"
    
    def query_stock(self, goods_name):
        """查询库存"""
        if not wdt_api:
            return f"要查 {goods_name} 的库存？\n\n旺店通 API 还没配置好，找老羊弄一下。"
        
        try:
            # 这里调用旺店通 API 查询库存
            # 简化版：返回提示，实际查询需要商品编码映射
            return f"查 {goods_name} 库存...\n\n旺店通已连接，但需要商品编码映射表。\n让老羊导入商品编码对照表，我就能查了。"
        except Exception as e:
            return f"查 {goods_name} 库存失败了: {e}\n找老羊看看。"
    
    def build_reply(self, to_user, from_user, content):
        """构建加密回复消息"""
        timestamp = str(int(datetime.now().timestamp()))
        nonce = ''.join([str(ord(c)) for c in timestamp])[:10]
        
        # 构建 XML
        xml = f"""<xml>
<ToUserName><![CDATA[{to_user}]]></ToUserName>
<FromUserName><![CDATA[{from_user}]]></FromUserName>
<CreateTime>{timestamp}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[{content}]]></Content>
</xml>"""
        
        # 加密
        encrypt = self.callback.encrypt_msg(xml, nonce, timestamp)
        if not encrypt:
            return None
        
        # 生成签名
        signature = self.callback.generate_signature(timestamp, nonce, encrypt)
        
        # 构建返回 XML
        return f"""<xml>
<Encrypt><![CDATA[{encrypt}]]></Encrypt>
<MsgSignature><![CDATA[{signature}]]></MsgSignature>
<TimeStamp>{timestamp}</TimeStamp>
<Nonce><![CDATA[{nonce}]]></Nonce>
</xml>"""


def test_url_verify():
    """测试 URL 验证"""
    handler = WeWorkHandler()
    
    # 模拟企业微信的验证请求
    test_params = {
        'msg_signature': ['test_sig'],
        'timestamp': ['1234567890'],
        'nonce': ['test_nonce'],
        'echostr': ['test_echostr']
    }
    
    result = handler.handle_get(test_params)
    print(f"验证结果: {result}")


if __name__ == '__main__':
    # 测试
    print("🧪 测试企业微信回调服务...")
    test_url_verify()
