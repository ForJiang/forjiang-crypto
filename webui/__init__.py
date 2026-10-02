"""本地 Web 界面：包一层 HTTP 服务，前端页面复用 forjiang_crypto 库。"""

from .server import main, serve

__all__ = ["main", "serve"]
