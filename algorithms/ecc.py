# ecc.py
import base64
import json
import time
import logging
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ECCEncryption:
    def __init__(self, curve=ec.SECP256R1()):
        """初始化 ECC 加密类
        
        Args:
            curve: 椭圆曲线，默认使用 SECP256R1 (NIST P-256)
        """
        self.curve = curve
        self.private_key = None
        self.public_key = None
        
        # 曲线参数映射表
        self.curve_sizes = {
            'SECP256R1': 256,
            'SECP384R1': 384,
            'SECP521R1': 521,
            'SECP224R1': 224,
            'SECP192R1': 192,
            'BRAINPOOLP256R1': 256,
            'BRAINPOOLP384R1': 384,
            'BRAINPOOLP512R1': 512,
            # 添加小写版本
            'secp256r1': 256,
            'secp384r1': 384,
            'secp521r1': 521,
            'secp224r1': 224,
            'secp192r1': 192,
            'brainpoolp256r1': 256,
            'brainpoolp384r1': 384,
            'brainpoolp512r1': 512,
        }
        
        # 曲线安全性映射表 - 包含更详细的安全评估
        self.curve_security = {
            'SECP256R1': {
                'security_bits': 128,
                'level': "高",
                'nist_compliance': True,
                'description': "NIST P-256曲线，提供128位安全强度，适合一般应用和TLS",
                'quantum_resistance': "低",
                'recommended_use': "适合一般商业应用、Web安全、移动应用",
                'equivalent_rsa': 3072
            },
            'SECP384R1': {
                'security_bits': 192,
                'level': "很高",
                'nist_compliance': True,
                'description': "NIST P-384曲线，提供192位安全强度，适合敏感数据",
                'quantum_resistance': "低",
                'recommended_use': "适合政府和金融机构的敏感数据",
                'equivalent_rsa': 7680
            },
            'SECP521R1': {
                'security_bits': 256,
                'level': "非常高",
                'nist_compliance': True,
                'description': "NIST P-521曲线，提供256位安全强度，适合高安全需求",
                'quantum_resistance': "低",
                'recommended_use': "适合最高级别的安全需求，如军事和国家安全应用",
                'equivalent_rsa': 15360
            },
            'SECP224R1': {
                'security_bits': 112,
                'level': "中等",
                'nist_compliance': True,
                'description': "NIST P-224曲线，提供112位安全强度，适合低安全需求",
                'quantum_resistance': "低",
                'recommended_use': "适合资源受限设备，但不推荐用于新系统",
                'equivalent_rsa': 2048
            },
            'SECP192R1': {
                'security_bits': 96,
                'level': "较低",
                'nist_compliance': True,
                'description': "NIST P-192曲线，提供96位安全强度，已不推荐使用",
                'quantum_resistance': "低",
                'recommended_use': "仅用于兼容旧系统，不推荐用于新应用",
                'equivalent_rsa': 1536
            },
            'BRAINPOOLP256R1': {
                'security_bits': 128,
                'level': "高",
                'nist_compliance': False,
                'description': "Brainpool 256位曲线，提供128位安全强度，非NIST标准",
                'quantum_resistance': "低",
                'recommended_use': "适合需要非NIST标准的应用",
                'equivalent_rsa': 3072
            },
            'BRAINPOOLP384R1': {
                'security_bits': 192,
                'level': "很高",
                'nist_compliance': False,
                'description': "Brainpool 384位曲线，提供192位安全强度，非NIST标准",
                'quantum_resistance': "低",
                'recommended_use': "适合需要非NIST标准的高安全应用",
                'equivalent_rsa': 7680
            },
            'BRAINPOOLP512R1': {
                'security_bits': 256,
                'level': "非常高",
                'nist_compliance': False,
                'description': "Brainpool 512位曲线，提供256位安全强度，非NIST标准",
                'quantum_resistance': "低",
                'recommended_use': "适合需要非NIST标准的最高安全应用",
                'equivalent_rsa': 15360
            },
            # 添加小写版本
            'secp256r1': {
                'security_bits': 128,
                'level': "高",
                'nist_compliance': True,
                'description': "NIST P-256曲线，提供128位安全强度，适合一般应用和TLS",
                'quantum_resistance': "低",
                'recommended_use': "适合一般商业应用、Web安全、移动应用",
                'equivalent_rsa': 3072
            },
            'secp384r1': {
                'security_bits': 192,
                'level': "很高",
                'nist_compliance': True,
                'description': "NIST P-384曲线，提供192位安全强度，适合敏感数据",
                'quantum_resistance': "低",
                'recommended_use': "适合政府和金融机构的敏感数据",
                'equivalent_rsa': 7680
            },
            'secp521r1': {
                'security_bits': 256,
                'level': "非常高",
                'nist_compliance': True,
                'description': "NIST P-521曲线，提供256位安全强度，适合高安全需求",
                'quantum_resistance': "低",
                'recommended_use': "适合最高级别的安全需求，如军事和国家安全应用",
                'equivalent_rsa': 15360
            },
            'secp224r1': {
                'security_bits': 112,
                'level': "中等",
                'nist_compliance': True,
                'description': "NIST P-224曲线，提供112位安全强度，适合低安全需求",
                'quantum_resistance': "低",
                'recommended_use': "适合资源受限设备，但不推荐用于新系统",
                'equivalent_rsa': 2048
            },
            'secp192r1': {
                'security_bits': 96,
                'level': "较低",
                'nist_compliance': True,
                'description': "NIST P-192曲线，提供96位安全强度，已不推荐使用",
                'quantum_resistance': "低",
                'recommended_use': "仅用于兼容旧系统，不推荐用于新应用",
                'equivalent_rsa': 1536
            },
            'brainpoolp256r1': {
                'security_bits': 128,
                'level': "高",
                'nist_compliance': False,
                'description': "Brainpool 256位曲线，提供128位安全强度，非NIST标准",
                'quantum_resistance': "低",
                'recommended_use': "适合需要非NIST标准的应用",
                'equivalent_rsa': 3072
            },
            'brainpoolp384r1': {
                'security_bits': 192,
                'level': "很高",
                'nist_compliance': False,
                'description': "Brainpool 384位曲线，提供192位安全强度，非NIST标准",
                'quantum_resistance': "低",
                'recommended_use': "适合需要非NIST标准的高安全应用",
                'equivalent_rsa': 7680
            },
            'brainpoolp512r1': {
                'security_bits': 256,
                'level': "非常高",
                'nist_compliance': False,
                'description': "Brainpool 512位曲线，提供256位安全强度，非NIST标准",
                'quantum_resistance': "低",
                'recommended_use': "适合需要非NIST标准的最高安全应用",
                'equivalent_rsa': 15360
            }
        }
        
        # 获取当前曲线的位长度
        self.curve_name = self.curve.name
        self.bit_length = self.curve_sizes.get(self.curve_name, 256)
        
        # 获取当前曲线的安全性信息
        self.security_info = self.curve_security.get(self.curve_name, {
            'security_bits': self.bit_length // 2,
            'level': "未知",
            'nist_compliance': False,
            'description': f"未知曲线 {self.curve_name}，安全性无法确定",
            'quantum_resistance': "低",
            'recommended_use': "无具体建议",
            'equivalent_rsa': self.bit_length * 12  # 粗略估计
        })

    def generate_keys(self):
        """生成 ECC 密钥对
        
        Returns:
            tuple: (public_key_pem, private_key_pem) PEM 格式的公钥和私钥
        """
        try:
            # 生成私钥
            private_key = ec.generate_private_key(
                self.curve,
                default_backend()
            )
            
            # 获取公钥
            public_key = private_key.public_key()
            
            # 将私钥序列化为 PEM 格式
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            # 将公钥序列化为 PEM 格式
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            self.private_key = private_key_pem
            self.public_key = public_key_pem
            
            return public_key_pem, private_key_pem
        except Exception as e:
            logger.error(f"ECC 密钥生成失败: {e}")
            raise

    def encrypt(self, plaintext, public_key_pem):
        """使用 ECC 公钥加密消息
        
        Args:
            plaintext: 要加密的明文
            public_key_pem: PEM 格式的公钥
            
        Returns:
            str: Base64 编码的加密数据
        """
        try:
            # 加载公钥
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # 获取最大加密长度（由于ECDH+AES结合，理论上没有明确限制，但为了安全性限制大小）
            max_encrypt_size = 1024  # 设置一个合理的块大小
            
            # 如果明文太长，分块加密
            plaintext_bytes = plaintext.encode('utf-8')
            if len(plaintext_bytes) > max_encrypt_size:
                chunks = []
                for i in range(0, len(plaintext_bytes), max_encrypt_size):
                    chunk = plaintext_bytes[i:i+max_encrypt_size]
                    encrypted_chunk = self._encrypt_chunk(chunk, public_key)
                    chunks.append(encrypted_chunk)
                
                # 返回分块加密的结果
                return json.dumps({"chunks": chunks, "chunked": True})
            else:
                # 单块加密
                return self._encrypt_chunk(plaintext_bytes, public_key)
        except Exception as e:
            logger.error(f"ECC 加密失败: {e}")
            raise
    
    def _encrypt_chunk(self, data, public_key):
        """加密单个数据块"""
        # 生成临时私钥
        ephemeral_private_key = ec.generate_private_key(
            self.curve,
            default_backend()
        )
        ephemeral_public_key = ephemeral_private_key.public_key()
        
        # 计算共享密钥
        shared_key = ephemeral_private_key.exchange(
            ec.ECDH(),
            public_key
        )
        
        # 使用 HKDF 派生对称加密密钥
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256 密钥长度
            salt=None,
            info=b'ECC-Encryption',
            backend=default_backend()
        ).derive(shared_key)
        
        # 生成随机 IV
        iv = os.urandom(16)  # AES 块大小
        
        # 使用 AES-GCM 模式加密
        encryptor = Cipher(
            algorithms.AES(derived_key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        
        # 加密数据
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # 序列化临时公钥
        ephemeral_public_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # 构造加密结果
        result = {
            'ephemeral_public_key': base64.b64encode(ephemeral_public_bytes).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(encryptor.tag).decode('utf-8')
        }
        
        # 返回 JSON 字符串，并进行 Base64 编码
        return base64.b64encode(json.dumps(result).encode('utf-8')).decode('utf-8')

    def decrypt(self, ciphertext_b64, private_key_pem):
        """使用 ECC 私钥解密消息
        
        Args:
            ciphertext_b64: Base64 编码的密文
            private_key_pem: PEM 格式的私钥
            
        Returns:
            str: 解密后的明文
        """
        try:
            # 检查是否为分块加密
            try:
                ciphertext_data = json.loads(ciphertext_b64)
                if ciphertext_data.get("chunked", False) == True:
                    chunks = ciphertext_data["chunks"]
                    plaintext_chunks = []
                    
                    for chunk in chunks:
                        decrypted_chunk = self._decrypt_chunk(chunk, private_key_pem)
                        plaintext_chunks.append(decrypted_chunk)
                    
                    # 合并所有块
                    return ''.join(plaintext_chunks)
            except (json.JSONDecodeError, KeyError):
                # 不是分块加密，继续正常解密
                pass
            
            return self._decrypt_chunk(ciphertext_b64, private_key_pem)
        except Exception as e:
            logger.error(f"ECC 解密失败: {e}")
            raise
    
    def _decrypt_chunk(self, chunk_b64, private_key_pem):
        """解密单个数据块"""
        # 解码 Base64
        ciphertext_json = base64.b64decode(chunk_b64).decode('utf-8')
        ciphertext_data = json.loads(ciphertext_json)
        
        # 加载私钥
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # 解析加密数据
        ephemeral_public_bytes = base64.b64decode(ciphertext_data['ephemeral_public_key'])
        iv = base64.b64decode(ciphertext_data['iv'])
        ciphertext = base64.b64decode(ciphertext_data['ciphertext'])
        tag = base64.b64decode(ciphertext_data['tag'])
        
        # 加载临时公钥
        ephemeral_public_key = serialization.load_pem_public_key(
            ephemeral_public_bytes,
            backend=default_backend()
        )
        
        # 计算共享密钥
        shared_key = private_key.exchange(
            ec.ECDH(),
            ephemeral_public_key
        )
        
        # 使用 HKDF 派生对称加密密钥
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256 密钥长度
            salt=None,
            info=b'ECC-Encryption',
            backend=default_backend()
        ).derive(shared_key)
        
        # 使用 AES-GCM 模式解密
        decryptor = Cipher(
            algorithms.AES(derived_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        
        # 解密数据
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode('utf-8')

    def performance_test(self, message_size=100, iterations=5):
        """性能测试
        
        Args:
            message_size: 测试消息大小（字节）
            iterations: 测试迭代次数
            
        Returns:
            dict: 包含各项性能指标的字典
        """
        results = {}
        
        # 测试密钥生成性能
        start_time = time.time()
        public_key, private_key = self.generate_keys()
        key_gen_time = time.time() - start_time
        results["key_generation_time"] = key_gen_time
        
        # 生成测试消息
        test_message = "A" * message_size
        
        # 多次测试加密性能并取平均值
        encrypt_times = []
        for _ in range(iterations):
            start_time = time.time()
            ciphertext = self.encrypt(test_message, public_key)
            encrypt_times.append(time.time() - start_time)
        results["encryption_time"] = sum(encrypt_times) / iterations
        
        # 多次测试解密性能并取平均值
        decrypt_times = []
        for _ in range(iterations):
            start_time = time.time()
            self.decrypt(ciphertext, private_key)
            decrypt_times.append(time.time() - start_time)
        results["decryption_time"] = sum(decrypt_times) / iterations
        
        # 测量密文长度
        if isinstance(ciphertext, str) and ciphertext.startswith("{"):
            # 处理分块加密的情况
            try:
                ciphertext_data = json.loads(ciphertext)
                if ciphertext_data.get("chunked", False) == True:
                    # 计算所有块的总大小
                    total_size = 0
                    for chunk in ciphertext_data["chunks"]:
                        chunk_json = json.loads(base64.b64decode(chunk).decode('utf-8'))
                        total_size += len(base64.b64decode(chunk_json["ciphertext"]))
                    results["ciphertext_size"] = total_size
                else:
                    # 单块加密
                    ciphertext_json = json.loads(base64.b64decode(ciphertext).decode('utf-8'))
                    results["ciphertext_size"] = len(base64.b64decode(ciphertext_json["ciphertext"]))
            except (json.JSONDecodeError, KeyError):
                # 解析失败，使用原始大小
                results["ciphertext_size"] = len(ciphertext)
        else:
            # 不是JSON格式，使用原始大小
            results["ciphertext_size"] = len(ciphertext)
        
        results["expansion_factor"] = results["ciphertext_size"] / message_size
        
        # 密钥大小
        results["public_key_size"] = len(public_key)
        results["private_key_size"] = len(private_key)
        results["curve_name"] = self.curve_name
        results["bit_length"] = self.bit_length
        
        # 详细安全性评估
        results["security_level"] = self.security_info['level']
        results["security_bits"] = self.security_info['security_bits']
        results["security_description"] = self.security_info['description']
        results["nist_compliance"] = self.security_info['nist_compliance']
        results["quantum_resistance"] = self.security_info['quantum_resistance']
        results["recommended_use"] = self.security_info['recommended_use']
        results["equivalent_rsa_bits"] = self.security_info['equivalent_rsa']
        
        return results


if __name__ == '__main__':
    ecc = ECCEncryption()
    pub, priv = ecc.generate_keys()
    message = "Hello, ECC!"
    ciphertext = ecc.encrypt(message, pub)
    decrypted = ecc.decrypt(ciphertext, priv)
    print(f"Original: {message}")
    print(f"Decrypted: {decrypted}")
    
    # 性能测试
    results = ecc.performance_test()
    for metric, value in results.items():
        print(f"{metric}: {value}")