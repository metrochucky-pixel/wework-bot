#!/usr/bin/env python3
"""
企业微信消息接收 HTTP 服务器
"""
import sys
import json
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, '/Users/chuck/.openclaw/workspace')
from wework_callback import WeWorkHandler

# 全局 handler
handler = WeWorkHandler()

class WeWorkHTTPHandler(BaseHTTPRequestHandler):
    """处理 HTTP 请求"""
    
    def log_message(self, format, *args):
        """自定义日志"""
        print(f"[{self.log_date_time_string()}] {format % args}")
    
    def do_GET(self):
        """处理 GET 请求（URL 验证）"""
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        
        print(f"\n📥 GET {self.path}")
        
        # 只处理回调路径
        if parsed.path == '/wechat/callback':
            result = handler.handle_get(query)
            
            if result:
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(result.encode())
                print(f"📤 返回: {result}")
            else:
                self.send_response(403)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"Forbidden")
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Not Found")
    
    def do_POST(self):
        """处理 POST 请求（接收消息）"""
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        
        print(f"\n📥 POST {self.path}")
        
        # 只处理回调路径
        if parsed.path == '/wechat/callback':
            # 读取请求体
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            
            print(f"📄 请求体:\n{body}")
            
            # 处理消息
            result = handler.handle_post(query, body)
            
            if result:
                self.send_response(200)
                self.send_header('Content-type', 'application/xml')
                self.end_headers()
                self.wfile.write(result.encode())
                print(f"📤 回复消息:\n{result}")
            else:
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"success")
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Not Found")


def run_server(port=8080):
    """启动服务器"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, WeWorkHTTPHandler)
    
    print(f"🚀 企业微信回调服务器启动...")
    print(f"   监听端口: {port}")
    print(f"   回调地址: http://api.wines-boutique.com/wechat/callback")
    print(f"\n按 Ctrl+C 停止\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n👋 服务器已停止")


if __name__ == '__main__':
    # 默认端口 8080，可以通过参数修改
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
