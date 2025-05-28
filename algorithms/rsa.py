# rsa.py
import random
import logging
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
import time
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def miller_rabin(n, k=5):
    """Miller-Rabin素性测试"""
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_large_prime(bit_length):
    """生成大素数"""
    while True:
        num = random.getrandbits(bit_length)
        num |= (1 << bit_length - 1) | 1  # 确保最高位和最低位为1
        if miller_rabin(num):
            return num


def gcd(a, b):
    """欧几里得算法求最大公约数"""
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """扩展欧几里得算法"""
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_gcd(b % a, a)
        return g, x - (b // a) * y, y


def mod_inverse(e, phi):
    """求模逆元"""
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % phi


class RSAEncryption:
    def __init__(self, bit_length=2048):
        self.bit_length = bit_length
        self.public_key = None
        self.private_key = None

    def generate_keys(self):
        """生成RSA密钥对"""
        try:
            # 使用 cryptography 库生成 RSA 密钥对
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.bit_length,
                backend=default_backend()
            )
            
            public_key = private_key.public_key()
            
            # 将密钥转换为 PEM 格式
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            self.public_key = public_pem
            self.private_key = private_pem
            
            return public_pem, private_pem
        except Exception as e:
            logger.error(f"RSA 密钥生成失败: {e}")
            raise

    def encrypt(self, plaintext, public_key_pem):
        """RSA加密"""
        try:
            # 加载公钥
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # 获取最大加密长度
            key_size = public_key.key_size
            max_encrypt_size = key_size // 8 - 42  # OAEP填充需要至少42字节
            
            # 如果明文太长，需要分块加密
            plaintext_bytes = plaintext.encode('utf-8')
            if len(plaintext_bytes) > max_encrypt_size:
                chunks = []
                for i in range(0, len(plaintext_bytes), max_encrypt_size):
                    chunk = plaintext_bytes[i:i+max_encrypt_size]
                    encrypted_chunk = public_key.encrypt(
                        chunk,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    chunks.append(base64.b64encode(encrypted_chunk).decode('utf-8'))
                
                # 返回分块加密的结果
                return json.dumps({"chunks": chunks, "chunked": True})
            else:
                # 加密数据
                ciphertext = public_key.encrypt(
                    plaintext_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # 返回 base64 编码的密文
                return base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            logger.error(f"RSA 加密失败: {e}")
            raise

    def decrypt(self, ciphertext, private_key_pem):
        """RSA解密"""
        try:
            # 加载私钥
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            
            # 检查是否为分块加密
            try:
                ciphertext_data = json.loads(ciphertext)
                if ciphertext_data.get("chunked", False) == True:
                    chunks = ciphertext_data["chunks"]
                    plaintext_chunks = []
                    
                    for chunk in chunks:
                        encrypted_chunk = base64.b64decode(chunk)
                        decrypted_chunk = private_key.decrypt(
                            encrypted_chunk,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        plaintext_chunks.append(decrypted_chunk)
                    
                    # 合并所有块
                    return b''.join(plaintext_chunks).decode('utf-8')
            except (json.JSONDecodeError, KeyError):
                # 不是分块加密，继续正常解密
                pass
            
            # 解码 base64 密文
            ciphertext_bytes = base64.b64decode(ciphertext)
            
            # 解密数据
            plaintext = private_key.decrypt(
                ciphertext_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return plaintext.decode('utf-8')
        except Exception as e:
            logger.error(f"RSA 解密失败: {e}")
            raise

    def sign(self, message, private_key_pem):
        """RSA签名"""
        try:
            # 加载私钥
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            
            # 签名
            signature = private_key.sign(
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            logger.error(f"RSA 签名失败: {e}")
            raise

    def verify(self, message, signature, public_key_pem):
        """RSA验证签名"""
        try:
            # 加载公钥
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # 解码签名
            signature_bytes = base64.b64decode(signature)
            
            # 验证签名
            public_key.verify(
                signature_bytes,
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
        except Exception as e:
            logger.error(f"RSA 验证签名失败: {e}")
            return False

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
        
        # 测试签名性能
        sign_times = []
        for _ in range(iterations):
            start_time = time.time()
            signature = self.sign(test_message, private_key)
            sign_times.append(time.time() - start_time)
        results["signing_time"] = sum(sign_times) / iterations
        
        # 测试验证性能
        verify_times = []
        for _ in range(iterations):
            start_time = time.time()
            self.verify(test_message, signature, public_key)
            verify_times.append(time.time() - start_time)
        results["verification_time"] = sum(verify_times) / iterations
        
        # 测量密文长度和签名长度
        if isinstance(ciphertext, str) and ciphertext.startswith("{"):
            # 处理分块加密的情况
            ciphertext_data = json.loads(ciphertext)
            if ciphertext_data.get("chunked", True):
                total_size = sum(len(base64.b64decode(chunk)) for chunk in ciphertext_data["chunks"])
                results["ciphertext_size"] = total_size
        else:
            results["ciphertext_size"] = len(base64.b64decode(ciphertext))
        
        results["signature_size"] = len(base64.b64decode(signature))
        results["expansion_factor"] = results["ciphertext_size"] / message_size
        
        # 密钥大小
        results["public_key_size"] = len(public_key)
        results["private_key_size"] = len(private_key)
        results["bit_length"] = self.bit_length
        
        # 安全性评估（基于密钥长度的简单评估）
        security_levels = {
            1024: "低（不推荐用于敏感数据）",
            2048: "中等（适合一般应用）",
            3072: "高（符合NIST推荐）",
            4096: "非常高（适合长期安全需求）"
        }
        results["security_level"] = security_levels.get(self.bit_length, "未知")
        
        return results


if __name__ == '__main__':
    rsa = RSAEncryption(bit_length=1024)
    pub, priv = rsa.generate_keys()
    message = "Hello, RSA!"
    ciphertext = rsa.encrypt(message, pub)
    decrypted = rsa.decrypt(ciphertext, priv)
    print(f"Original: {message}")
    print(f"Decrypted: {decrypted}")
    
    # 测试签名和验证
    signature = rsa.sign(message, priv)
    is_valid = rsa.verify(message, signature, pub)
    print(f"Signature valid: {is_valid}")
    
    # 性能测试
    results = rsa.performance_test()
    for metric, value in results.items():
        print(f"{metric}: {value}")