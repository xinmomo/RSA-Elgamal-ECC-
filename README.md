# 公钥密码算法交互系统

本项目是一个基于FastAPI框架开发的公钥密码算法交互系统，支持RSA、ElGamal、ECC三种主流公钥密码算法的演示、比较和性能测试。系统提供了密钥生成、加解密功能，并通过Web界面和RESTful API对外提供服务，适合教学、实验和算法对比研究。

## 系统功能

- **三种经典公钥密码算法支持**
  - RSA算法
  - ElGamal算法
  - ECC椭圆曲线算法
- **密钥管理**
  - 密钥对生成
  - 公私钥显示与存储
- **加密解密**
  - 公钥加密
  - 私钥解密
  - 明文/密文处理
- **性能测试与比较**
  - 密钥生成时间
  - 加密/解密速度
  - 密文扩展因子
  - 安全级别评估
- **友好的Web界面**
  - 交互式操作
  - 实时结果显示
  - 算法切换与比较

## 环境要求

- Python 3.8 及以上
- 依赖包:
  - fastapi==0.111.0
  - uvicorn==0.30.1
  - pycryptodome==3.20.0
  - python-multipart==0.0.9
  - jinja2==3.1.2
  - cryptography==41.0.5
  - pydantic==2.4.2

## 安装与运行

1. **克隆项目**
   ```bash
   git clone <repository-url>
   cd fastapi
   ```

2. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

3. **启动服务**
   ```bash
   python main.py
   ```
   或者
   ```bash
   uvicorn main:app --reload
   ```

4. **访问系统**
   - Web界面: 打开浏览器访问 [http://localhost:8000](http://localhost:8000)
   - API文档: 打开浏览器访问 [http://localhost:8000/docs](http://localhost:8000/docs)

## API接口

系统提供以下RESTful API接口:

### RSA算法
- `POST /api/encryption/rsa/generate`: 生成RSA密钥对
- `POST /api/encryption/rsa/encrypt`: RSA加密
- `POST /api/encryption/rsa/decrypt`: RSA解密
- `POST /api/encryption/performance/rsa`: RSA性能测试

### ElGamal算法
- `POST /api/encryption/elgamal/generate`: 生成ElGamal密钥对
- `POST /api/encryption/elgamal/encrypt`: ElGamal加密
- `POST /api/encryption/elgamal/decrypt`: ElGamal解密
- `POST /api/encryption/performance/elgamal`: ElGamal性能测试

### ECC算法
- `POST /api/encryption/ecc/generate`: 生成ECC密钥对
- `POST /api/encryption/ecc/encrypt`: ECC加密
- `POST /api/encryption/ecc/decrypt`: ECC解密
- `POST /api/encryption/performance/ecc`: ECC性能测试

## 项目结构

```
fastapi/
├── main.py                # FastAPI主入口
├── requirements.txt       # 依赖包列表
├── algorithms/            # 算法实现目录
│   ├── __init__.py
│   ├── rsa.py            # RSA算法实现
│   ├── elgamal.py        # ElGamal算法实现
│   └── ecc.py            # ECC算法实现
├── routes/               # API路由目录
│   └── encryption.py     # 加密算法API路由
├── templates/            # HTML模板目录
│   ├── index.html        # 主页模板
│   └── performance.html  # 性能比较页面模板
├── static/               # 静态资源目录
└── tests/                # 测试代码目录
```

## 系统特点

1. **模块化设计**：算法实现与接口分离，便于扩展和维护
2. **直观的Web界面**：提供用户友好的交互体验
3. **完整的API文档**：自动生成的Swagger文档，便于集成和调用
4. **性能测试功能**：支持不同算法的性能对比和分析
5. **安全性考虑**：采用标准加密库实现，保证算法正确性

## 注意事项

- 本系统仅用于教学、实验和算法对比研究，不建议直接用于生产环境
- 密钥和敏感数据请妥善保管，避免泄露
- 性能测试结果仅供参考，实际性能与硬件、参数设置等有关

## 参考资料

- [FastAPI官方文档](https://fastapi.tiangolo.com/)
- [PyCryptodome文档](https://www.pycryptodome.org/)
- [密码学原理与实践](https://www.amazon.com/Cryptography-Theory-Practice-Douglas-Stinson/dp/1138197017) 