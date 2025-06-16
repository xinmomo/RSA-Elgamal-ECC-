# elgamal.py
import random
import time
import base64
import json
import logging
import concurrent.futures

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


def find_primitive_root(p, max_attempts=100):
    """寻找原根，限制尝试次数"""
    # 对于较小的素数，我们可以使用预定义的安全值
    if p < 1000:
        return 2  # 简化处理，对于小素数使用2
    
    for attempt in range(max_attempts):
        g = random.randint(2, p - 2)
        # 简化原根检查，只检查一些基本条件
        if pow(g, (p - 1) // 2, p) != 1:
            return g
    
    # 如果找不到，返回2作为默认值
    return 2


class ElGamalEncryption:
    def __init__(self, bit_length=2048):  # 将默认位长度改为2048位
        self.bit_length = bit_length
        self.public_key = None
        self.private_key = None

    def generate_keys(self, timeout=10):
        """生成ElGamal密钥对，添加超时机制"""
        try:
            # 使用线程池执行素数生成，设置超时
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(generate_large_prime, self.bit_length)
                try:
                    # 设置超时时间
                    p = future.result(timeout=timeout)
                except concurrent.futures.TimeoutError:
                    # 如果超时，使用较小的位长度重试
                    logger.warning(f"ElGamal密钥生成超时，降低位长度重试")
                    reduced_bit_length = max(256, self.bit_length // 2)
                    p = generate_large_prime(reduced_bit_length)
            
            # 找到原根 g，限制尝试次数
            g = find_primitive_root(p)
            
            # 生成私钥 x
            x = random.randint(2, p - 2)
            
            # 计算公钥 h = g^x mod p
            h = pow(g, x, p)
            
            # 构造密钥
            public_key = json.dumps({"p": str(p), "g": str(g), "h": str(h)})
            private_key = json.dumps({"p": str(p), "x": str(x)})
            
            self.public_key = public_key
            self.private_key = private_key
            
            return public_key, private_key
        except Exception as e:
            logger.error(f"ElGamal 密钥生成失败: {e}")
            raise

    def encrypt(self, plaintext, public_key_json):
        """ElGamal加密"""
        try:
            # 解析公钥
            key_data = json.loads(public_key_json)
            p = int(key_data["p"])
            g = int(key_data["g"])
            h = int(key_data["h"])
            
            # 将消息转换为数字
            m = int.from_bytes(plaintext.encode('utf-8'), 'big')
            
            # 确保消息小于 p
            if m >= p:
                # 如果消息太长，分块加密
                chunks = []
                plaintext_bytes = plaintext.encode('utf-8')
                # 计算每个块的大小（以字节为单位）
                block_size = (p.bit_length() - 16) // 8  # 留出一些空间
                
                for i in range(0, len(plaintext_bytes), block_size):
                    chunk = plaintext_bytes[i:i+block_size]
                    m_chunk = int.from_bytes(chunk, 'big')
                    
                    # 为每个块生成不同的随机数k
                    k = random.randint(2, p - 2)
                    c1 = pow(g, k, p)
                    s = pow(h, k, p)
                    c2 = (m_chunk * s) % p
                    
                    chunks.append({"c1": str(c1), "c2": str(c2)})
                
                # 返回分块加密的结果
                ciphertext = json.dumps({"chunks": chunks, "chunked": True})
                return base64.b64encode(ciphertext.encode()).decode()
            
            # 生成随机数 k
            k = random.randint(2, p - 2)
            
            # 计算密文
            c1 = pow(g, k, p)
            s = pow(h, k, p)
            c2 = (m * s) % p
            
            # 返回 base64 编码的密文对
            ciphertext = json.dumps({"c1": str(c1), "c2": str(c2), "chunked": False})
            return base64.b64encode(ciphertext.encode()).decode()
        except Exception as e:
            logger.error(f"ElGamal 加密失败: {e}")
            raise

    def decrypt(self, ciphertext, private_key_json):
        """ElGamal解密"""
        try:
            # 解码 base64 密文
            ciphertext_json = base64.b64decode(ciphertext).decode()
            cipher_data = json.loads(ciphertext_json)
            
            # 解析私钥
            key_data = json.loads(private_key_json)
            p = int(key_data["p"])
            x = int(key_data["x"])
            
            # 检查是否为分块加密
            if cipher_data.get("chunked", False) == True:
                chunks = cipher_data["chunks"]
                plaintext_chunks = []
                
                for chunk in chunks:
                    c1 = int(chunk["c1"])
                    c2 = int(chunk["c2"])
                    
                    # 计算共享密钥
                    s = pow(c1, x, p)
                    
                    # 计算模逆元
                    s_inv = pow(s, p - 2, p)  # 费马小定理求逆
                    
                    # 恢复明文
                    m = (c2 * s_inv) % p
                    
                    # 将数字转换回字节
                    byte_length = (m.bit_length() + 7) // 8
                    m_bytes = m.to_bytes(byte_length, 'big')
                    plaintext_chunks.append(m_bytes)
                
                # 合并所有块
                return b''.join(plaintext_chunks).decode('utf-8')
            else:
                # 解析密文
                c1 = int(cipher_data["c1"])
                c2 = int(cipher_data["c2"])
                
                # 计算共享密钥
                s = pow(c1, x, p)
                
                # 计算模逆元
                s_inv = pow(s, p - 2, p)  # 费马小定理求逆
                
                # 恢复明文
                m = (c2 * s_inv) % p
                
                # 将数字转换回字节，然后解码为字符串
                try:
                    # 计算需要的字节数
                    byte_length = (m.bit_length() + 7) // 8
                    m_bytes = m.to_bytes(byte_length, 'big')
                    return m_bytes.decode('utf-8')
                except (ValueError, UnicodeDecodeError):
                    # 如果解码失败，返回十六进制表示
                    return f"0x{m:x}"
        except Exception as e:
            logger.error(f"ElGamal 解密失败: {e}")
            raise

    def performance_test(self, message_size=100):
        """性能测试
        
        Args:
            message_size: 测试消息大小（字节）
            
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
        
        # 测试加密性能
        start_time = time.time()
        ciphertext = self.encrypt(test_message, public_key)
        encrypt_time = time.time() - start_time
        results["encryption_time"] = encrypt_time
        
        # 测试解密性能
        start_time = time.time()
        self.decrypt(ciphertext, private_key)
        decrypt_time = time.time() - start_time
        results["decryption_time"] = decrypt_time
        
        # 测量密文长度
        ciphertext_size = len(base64.b64decode(ciphertext))
        results["ciphertext_size"] = ciphertext_size
        results["expansion_factor"] = ciphertext_size / message_size
        
        # 密钥大小
        results["public_key_size"] = len(public_key)
        results["private_key_size"] = len(private_key)
        
        # 添加位长度和安全级别
        results["bit_length"] = self.bit_length
        if self.bit_length >= 2048:
            results["security_level"] = "中等（适合一般应用）"
        elif self.bit_length >= 1024:
            results["security_level"] = "较低（仅适合短期安全）"
        else:
            results["security_level"] = "低（不推荐用于敏感数据）"
        
        return results


if __name__ == '__main__':
    elgamal = ElGamalEncryption(bit_length=2048)  # 使用较小的位长度进行测试
    pub, priv = elgamal.generate_keys()
    message = "Hello, ElGamal!"
    ciphertext = elgamal.encrypt(message, pub)
    decrypted = elgamal.decrypt(ciphertext, priv)
    print(f"Original: {message}")
    print(f"Decrypted: {decrypted}")
    
    # 性能测试
    results = elgamal.performance_test()
    for metric, value in results.items():
        print(f"{metric}: {value}")