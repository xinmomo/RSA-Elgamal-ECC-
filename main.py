from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import logging
from routes.encryption import router

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="公钥密码算法交互系统")

# 挂载加密相关路由
app.include_router(router)

# 挂载静态文件
app.mount("/static", StaticFiles(directory="static"), name="static")

# 模板配置
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """渲染主页"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/performance", response_class=HTMLResponse)
async def performance_comparison(request: Request):
    """渲染性能比较页面"""
    return templates.TemplateResponse("performance.html", {"request": request})

@app.get("/health")
async def health_check():
    """健康检查端点"""
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    logger.info("启动公钥密码算法交互系统...")
    uvicorn.run(app, host="0.0.0.0", port=8000)