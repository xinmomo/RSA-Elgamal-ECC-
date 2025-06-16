import logging
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
from algorithms.rsa import RSAEncryption
from algorithms.elgamal import ElGamalEncryption
from algorithms.ecc import ECCEncryption
from cryptography.hazmat.primitives.asymmetric import ec
import time

router = APIRouter(prefix="/api/encryption", tags=["Encryption API"])
logger = logging.getLogger(__name__)

# 请求模型
class EncryptRequest(BaseModel):
    plaintext: str
    public_key: str

class DecryptRequest(BaseModel):
    ciphertext: str
    private_key: str

class PerformanceTestRequest(BaseModel):
    message_size: int = 100
    iterations: int = 100

class ECCGenerateRequest(BaseModel):
    curve_name: str = "SECP256R1"  # 默认使用P-256曲线

class KeyGenerateResponse(BaseModel):
    public_key: str
    private_key: str

class EncryptResponse(BaseModel):
    ciphertext: str

class DecryptResponse(BaseModel):
    plaintext: str

class PerformanceResponse(BaseModel):
    key_generation_time: float
    encryption_time: float
    decryption_time: float
    ciphertext_size: int
    expansion_factor: float
    security_level: str = None
    curve_name: str = None # ECC特有
    bit_length: int = None # ElGamal特有

# 添加ECC曲线信息API
@router.get('/ecc/curves')
def get_ecc_curves():
    """获取支持的ECC曲线列表及其安全性信息"""
    try:
        # 创建临时ECC对象以获取曲线信息
        ecc = ECCEncryption()
        
        # 获取支持的曲线列表
        supported_curves = []
        for curve_name in ecc.curve_security.keys():
            security_info = ecc.curve_security[curve_name]
            supported_curves.append({
                'name': curve_name,
                'bits': ecc.curve_sizes.get(curve_name, 0),
                'security_bits': security_info['security_bits'],
                'level': security_info['level'],
                'description': security_info['description'],
                'nist_compliance': security_info['nist_compliance'],
                'quantum_resistance': security_info['quantum_resistance'],
                'recommended_use': security_info['recommended_use'],
                'equivalent_rsa': security_info['equivalent_rsa']
            })
        
        # 按安全位数排序
        supported_curves.sort(key=lambda x: x['security_bits'], reverse=True)
        
        return JSONResponse(content={
            'curves': supported_curves
        })
    except Exception as e:
        logger.error(f'获取ECC曲线信息失败: {e}')
        return JSONResponse(content={'error': str(e)}, status_code=500)

# 修改ECC密钥生成API，支持选择曲线
@router.post('/ecc/generate_keys')
def generate_ecc_keys(request: Optional[ECCGenerateRequest] = None):
    try:
        if request is None:
            request = ECCGenerateRequest()
        
        # 根据曲线名称选择相应的曲线
        curve = None
        curve_name = request.curve_name.upper()
        
        if curve_name == "SECP256R1":
            curve = ec.SECP256R1()
        elif curve_name == "SECP384R1":
            curve = ec.SECP384R1()
        elif curve_name == "SECP521R1":
            curve = ec.SECP521R1()
        elif curve_name == "SECP224R1":
            curve = ec.SECP224R1()
        elif curve_name == "SECP192R1":
            curve = ec.SECP192R1()
        elif curve_name == "BRAINPOOLP256R1":
            curve = ec.BrainpoolP256R1()
        elif curve_name == "BRAINPOOLP384R1":
            curve = ec.BrainpoolP384R1()
        elif curve_name == "BRAINPOOLP512R1":
            curve = ec.BrainpoolP512R1()
        else:
            # 默认使用P-256曲线
            curve = ec.SECP256R1()
            curve_name = "SECP256R1"
        
        # 使用选定的曲线创建ECC对象
        ecc = ECCEncryption(curve=curve)
        public_key, private_key = ecc.generate_keys()
        
        # 获取曲线的安全性信息
        security_info = ecc.security_info
        
        logger.info(f'ECC 密钥生成成功，使用曲线: {curve_name}')
        return JSONResponse(content={
            'public_key': public_key,
            'private_key': private_key,
            'curve_name': curve_name,
            'bit_length': ecc.bit_length,
            'security_level': security_info['level'],
            'security_bits': security_info['security_bits'],
            'security_description': security_info['description'],
            'equivalent_rsa_bits': security_info['equivalent_rsa']
        })
    except Exception as e:
        logger.error(f'ECC 密钥生成失败: {e}')
        return JSONResponse(content={'error': str(e)}, status_code=500)

# 添加ECC安全性评估API
@router.get('/ecc/security_assessment')
def ecc_security_assessment(curve_name: str = "SECP256R1"):
    try:
        # 根据曲线名称选择相应的曲线
        curve = None
        curve_name = curve_name.upper()
        
        if curve_name == "SECP256R1":
            curve = ec.SECP256R1()
        elif curve_name == "SECP384R1":
            curve = ec.SECP384R1()
        elif curve_name == "SECP521R1":
            curve = ec.SECP521R1()
        elif curve_name == "SECP224R1":
            curve = ec.SECP224R1()
        elif curve_name == "SECP192R1":
            curve = ec.SECP192R1()
        elif curve_name == "BRAINPOOLP256R1":
            curve = ec.BrainpoolP256R1()
        elif curve_name == "BRAINPOOLP384R1":
            curve = ec.BrainpoolP384R1()
        elif curve_name == "BRAINPOOLP512R1":
            curve = ec.BrainpoolP512R1()
        else:
            return JSONResponse(content={'error': f'不支持的曲线: {curve_name}'}, status_code=400)
        
        # 使用选定的曲线创建ECC对象
        ecc = ECCEncryption(curve=curve)
        
        # 获取曲线的安全性信息
        security_info = ecc.security_info
        
        # 返回详细的安全性评估信息
        return JSONResponse(content={
            'curve_name': curve_name,
            'bit_length': ecc.bit_length,
            'security_bits': security_info['security_bits'],
            'security_level': security_info['level'],
            'description': security_info['description'],
            'nist_compliance': security_info['nist_compliance'],
            'quantum_resistance': security_info['quantum_resistance'],
            'recommended_use': security_info['recommended_use'],
            'equivalent_rsa_bits': security_info['equivalent_rsa'],
            'comparison': {
                'vs_rsa': f"相当于{security_info['equivalent_rsa']}位RSA密钥的安全强度",
                'vs_symmetric': f"相当于{security_info['security_bits']}位对称密钥的安全强度"
            },
            'recommendations': [
                f"该曲线提供{security_info['security_bits']}位的安全强度",
                f"适用场景: {security_info['recommended_use']}",
                "ECC算法对量子计算攻击的抵抗力较弱，对于需要长期安全保障的数据，建议考虑后量子密码算法"
            ]
        })
    except Exception as e:
        logger.error(f'ECC 安全性评估失败: {e}')
        return JSONResponse(content={'error': str(e)}, status_code=500)

@router.post('/rsa/generate', response_model=KeyGenerateResponse)
async def rsa_generate_keys_api():
    """生成RSA密钥对"""
    try:
        rsa = RSAEncryption(2048)
        public_key, private_key = rsa.generate_keys()
        return {"public_key": public_key, "private_key": private_key}
    except Exception as e:
        logger.error(f"RSA 密钥生成失败: {e}")
        raise HTTPException(status_code=500, detail=f"RSA 密钥生成失败: {str(e)}")

@router.post('/elgamal/generate', response_model=KeyGenerateResponse)
async def elgamal_generate_keys_api():
    """生成ElGamal密钥对"""
    try:
        elgamal = ElGamalEncryption(2048)  # 使用2048位长度以提高安全性
        public_key, private_key = elgamal.generate_keys()
        return {"public_key": public_key, "private_key": private_key}
    except Exception as e:
        logger.error(f"ElGamal 密钥生成失败: {e}")
        raise HTTPException(status_code=500, detail=f"ElGamal 密钥生成失败: {str(e)}")

@router.post('/ecc/generate', response_model=KeyGenerateResponse)
async def ecc_generate_keys_api():
    """生成ECC密钥对"""
    try:
        ecc = ECCEncryption()  # 使用默认的P-256曲线
        public_key, private_key = ecc.generate_keys()
        return {"public_key": public_key, "private_key": private_key}
    except Exception as e:
        logger.error(f"ECC 密钥生成失败: {e}")
        raise HTTPException(status_code=500, detail=f"ECC 密钥生成失败: {str(e)}")

@router.post('/rsa/encrypt', response_model=EncryptResponse)
async def rsa_encrypt_api(req: EncryptRequest):
    """RSA加密"""
    try:
        rsa = RSAEncryption()
        ciphertext = rsa.encrypt(req.plaintext, req.public_key)
        return {"ciphertext": ciphertext}
    except Exception as e:
        logger.error(f"RSA 加密失败: {e}")
        raise HTTPException(status_code=500, detail=f"RSA 加密失败: {str(e)}")

@router.post('/rsa/decrypt', response_model=DecryptResponse)
async def rsa_decrypt_api(req: DecryptRequest):
    """RSA解密"""
    try:
        rsa = RSAEncryption()
        plaintext = rsa.decrypt(req.ciphertext, req.private_key)
        return {"plaintext": plaintext}
    except Exception as e:
        logger.error(f"RSA 解密失败: {e}")
        raise HTTPException(status_code=500, detail=f"RSA 解密失败: {str(e)}")

@router.post('/elgamal/encrypt', response_model=EncryptResponse)
async def elgamal_encrypt_api(req: EncryptRequest):
    """ElGamal加密"""
    try:
        elgamal = ElGamalEncryption()
        ciphertext = elgamal.encrypt(req.plaintext, req.public_key)
        return {"ciphertext": ciphertext}
    except Exception as e:
        logger.error(f"ElGamal 加密失败: {e}")
        raise HTTPException(status_code=500, detail=f"ElGamal 加密失败: {str(e)}")

@router.post('/elgamal/decrypt', response_model=DecryptResponse)
async def elgamal_decrypt_api(req: DecryptRequest):
    """ElGamal解密"""
    try:
        elgamal = ElGamalEncryption()
        plaintext = elgamal.decrypt(req.ciphertext, req.private_key)
        return {"plaintext": plaintext}
    except Exception as e:
        logger.error(f"ElGamal 解密失败: {e}")
        raise HTTPException(status_code=500, detail=f"ElGamal 解密失败: {str(e)}")

@router.post('/ecc/encrypt', response_model=EncryptResponse)
async def ecc_encrypt_api(req: EncryptRequest):
    """ECC加密"""
    try:
        ecc = ECCEncryption()
        ciphertext = ecc.encrypt(req.plaintext, req.public_key)
        return {"ciphertext": ciphertext}
    except Exception as e:
        logger.error(f"ECC 加密失败: {e}")
        raise HTTPException(status_code=500, detail=f"ECC 加密失败: {str(e)}")

@router.post('/ecc/decrypt', response_model=DecryptResponse)
async def ecc_decrypt_api(req: DecryptRequest):
    """ECC解密"""
    try:
        ecc = ECCEncryption()
        plaintext = ecc.decrypt(req.ciphertext, req.private_key)
        return {"plaintext": plaintext}
    except Exception as e:
        logger.error(f"ECC 解密失败: {e}")
        raise HTTPException(status_code=500, detail=f"ECC 解密失败: {str(e)}")

@router.get('/ecc/performance', response_model=PerformanceResponse)
async def ecc_performance_api():
    """ECC性能测试"""
    try:
        ecc = ECCEncryption()
        results = ecc.performance_test()
        return JSONResponse(content=results)
    except Exception as e:
        logger.error(f'ECC 性能测试失败: {e}')
        return JSONResponse(content={'error': str(e)}, status_code=500)

@router.post('/performance/ecc/{curve_name}', response_model=PerformanceResponse)
async def ecc_performance_test_with_curve(curve_name: str, request: PerformanceTestRequest):
    try:
        # 根据曲线名称选择相应的曲线
        curve = None
        curve_name = curve_name.upper()
        
        if curve_name == "SECP256R1":
            curve = ec.SECP256R1()
        elif curve_name == "SECP384R1":
            curve = ec.SECP384R1()
        elif curve_name == "SECP521R1":
            curve = ec.SECP521R1()
        elif curve_name == "SECP224R1":
            curve = ec.SECP224R1()
        elif curve_name == "SECP192R1":
            curve = ec.SECP192R1()
        elif curve_name == "BRAINPOOLP256R1":
            curve = ec.BrainpoolP256R1()
        elif curve_name == "BRAINPOOLP384R1":
            curve = ec.BrainpoolP384R1()
        elif curve_name == "BRAINPOOLP512R1":
            curve = ec.BrainpoolP512R1()
        else:
            return JSONResponse(content={'error': f'不支持的曲线: {curve_name}'}, status_code=400)
        
        # 使用选定的曲线创建ECC对象
        ecc = ECCEncryption(curve=curve)
        results = ecc.performance_test(message_size=request.message_size, iterations=request.iterations)
        return JSONResponse(content=results)
    except Exception as e:
        logger.error(f'ECC 性能测试失败: {e}')
        return JSONResponse(content={'error': str(e)}, status_code=500)

@router.post('/performance/compare', response_model=PerformanceResponse)
async def compare_performance(request: PerformanceTestRequest):
    try:
        # 运行三种算法的性能测试
        rsa = RSAEncryption(2048)
        elgamal = ElGamalEncryption(2048)  # 使用2048位长度以提高安全性
        ecc = ECCEncryption()
        
        rsa_results = rsa.performance_test(message_size=request.message_size, iterations=request.iterations)
        elgamal_results = elgamal.performance_test(message_size=request.message_size)
        ecc_results = ecc.performance_test(message_size=request.message_size, iterations=request.iterations)
        
        # 返回比较结果
        return JSONResponse(content={
            'rsa': rsa_results,
            'elgamal': elgamal_results,
            'ecc': ecc_results,
            'message_size': request.message_size,
            'iterations': request.iterations
        })
    except Exception as e:
        logger.error(f'性能比较测试失败: {e}')
        return JSONResponse(content={'error': str(e)}, status_code=500)

@router.post('/performance/rsa', response_model=PerformanceResponse)
async def rsa_performance_test(request: PerformanceTestRequest):
    try:
        # 创建RSA对象并运行性能测试
        rsa = RSAEncryption(2048)
        results = rsa.performance_test(message_size=request.message_size, iterations=request.iterations)
        return JSONResponse(content=results)
    except Exception as e:
        logger.error(f'RSA 性能测试失败: {e}')
        return JSONResponse(content={'error': str(e)}, status_code=500)

@router.post('/performance/elgamal', response_model=PerformanceResponse)
async def elgamal_performance_test(request: PerformanceTestRequest):
    try:
        # 创建ElGamal对象并运行性能测试
        elgamal = ElGamalEncryption(2048)  # 使用2048位长度以提高安全性
        results = elgamal.performance_test(message_size=request.message_size)
        
        # 添加密钥长度和安全级别信息
        results["bit_length"] = 2048
        results["security_level"] = "中等（适合一般应用）"
        
        return JSONResponse(content=results)
    except Exception as e:
        logger.error(f'ElGamal 性能测试失败: {e}')
        return JSONResponse(content={'error': str(e)}, status_code=500)

@router.post('/performance/ecc', response_model=PerformanceResponse)
async def ecc_performance_test(request: PerformanceTestRequest):
    try:
        # 创建ECC对象并运行性能测试
        ecc = ECCEncryption()  # 使用默认曲线
        results = ecc.performance_test(message_size=request.message_size, iterations=request.iterations)
        return JSONResponse(content=results)
    except Exception as e:
        logger.error(f'ECC 性能测试失败: {e}')
        return JSONResponse(content={'error': str(e)}, status_code=500)

logging.basicConfig(level=logging.INFO)