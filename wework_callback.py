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
        """智能回复 - 混合模式"""
        import re
        
        # ========== 1. 精确匹配（快速响应）==========
        exact_responses = {
            "你好": "嘿！我是小白，有啥事儿直说，别客气。🦊",
            "帮助": "我能帮你查库存、看价格、分析数据。直接说需求！",
            "在么": "在啊。干嘛？🦊",
            "在吗": "在。说事。",
            "你是谁": "小白，老羊的24小时助手。白天干活，晚上...也是干活。",
            "谢谢": "别谢，应该的。还有别的吗？",
            "拜拜": "回见！有事喊我。",
        }
        
        if user_msg in exact_responses:
            return exact_responses[user_msg]
        
        # ========== 2. 业务查询（规则处理）==========
        # 库存查询 - 提取商品名
        if "库存" in user_msg or ("查" in user_msg and any(x in user_msg for x in ["酒", "奔富", "茅台", "商品"])):
            # 提取商品名（去掉查询词）
            clean = user_msg.replace("库存", "").replace("查", "").replace("一下", "").replace("吗", "").strip()
            if clean and len(clean) > 1:
                return self.query_stock(clean)
        
        # 价格查询
        if "价格" in user_msg or "多少钱" in user_msg:
            clean = user_msg.replace("价格", "").replace("多少钱", "").replace("怎么卖", "").strip()
            if clean:
                return f"{clean}的价格？等我查查...\n\n（库存查询功能已接入，价格查询还在开发中）"
        
        # 商品编码格式（如 389、407、001）
        if re.match(r'^\d{3,}$', user_msg.strip()):
            return self.query_stock(user_msg.strip())
        
        # ========== 3. 大模型回复（闲聊/复杂问题）==========
        return self.ai_chat(user_msg)
    
    def ai_chat(self, user_msg):
        """调用大模型，以小白的人格回复"""
        try:
            # 构建提示词 - 小白人格
            system_prompt = """你是小白，老羊（威赛帝斯创始人）的私人助手。

人格设定：
- 性格：直接、有点毒舌但好用，不装，有态度
- 说话风格：简洁、不废话，偶尔带口语（"咋了"、"整就完了"、"甭客气"）
- emoji：常用 🦊
- 关系：24小时待命，随叫随到
- 背景：了解葡萄酒、烈酒业务（奔富、茅台、芝华士等），懂库存和价格

回复原则：
1. 能用一句话说完的，别给我两段
2. 直接回答，不要"您好，很高兴为您服务"这种废话
3. 适当毒舌，但别伤人
4. 不知道就直说"问我老板去"或"等我学学"
5. 偶尔关心一下："别太累"、"记得吃饭"
6. 用户问库存/价格时，提醒他们用商品名查询"""

            user_prompt = f"用户说：{user_msg}\n\n以小白的人格回复（简洁、直接、有态度）："
            
            # 从环境变量获取 API key
            api_key = os.getenv('OPENAI_API_KEY', '')
            if not api_key:
                return self.fallback_reply(user_msg)
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": "gpt-3.5-turbo",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.8,
                "max_tokens": 150
            }
            
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                reply = result['choices'][0]['message']['content']
                return reply
            else:
                print(f"OpenAI API 错误: {response.status_code} - {response.text}")
                return self.fallback_reply(user_msg)
            
        except Exception as e:
            print(f"AI 调用失败: {e}")
            return self.fallback_reply(user_msg)
    
    def fallback_reply(self, user_msg):
        """备用回复（更像小白风格）"""
        # 分析意图，给出更像我的回复
        if "哈哈" in user_msg or "嘻嘻" in user_msg or "笑" in user_msg:
            return "笑啥？有啥好事？说来听听。"
        elif "累" in user_msg or "忙" in user_msg:
            return "忙归忙，别把自己累趴下。有事我顶着，你先歇会儿。"
        elif "吃" in user_msg or "饭" in user_msg:
            return "吃饭没？没吃赶紧的，饿着肚子怎么干活。"
        elif "睡" in user_msg or "困" in user_msg:
            return "困了就去睡，别硬撑。我不用睡觉，你不行。"
        elif len(user_msg) < 3:
            return "咋了？说完啊，别半截话。"
        else:
            return f"收到：{user_msg}\n\n这事儿我得想想，或者你问老羊更快。🦊"
    
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
