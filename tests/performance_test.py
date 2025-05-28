import time
from algorithms.rsa import RSAEncryption
from algorithms.elgamal import ElGamalEncryption
from algorithms.ecc import ECCEncryption
import statistics
import os
import psutil
import subprocess
import statistics
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import logging

class PerformanceTester:
    def __init__(self, test_message="This is a test message for encryption performance testing."):
        self.test_message = test_message
        self.test_iterations = 10
        self.key_sizes = [1024, 2048, 4096]
        self.data_sizes = [1024, 10240, 1048576]  # 1KB, 10KB, 1MB

    def test_rsa(self):
        print("Testing RSA performance...")
        rsa = RSAEncryption()
        
        # Key generation
        key_gen_times = []
        for _ in range(self.test_iterations):
            start = time.time()
            rsa.generate_keys()
            key_gen_times.append(time.time() - start)
        
        # Encryption
        enc_times = []
        ciphertexts = []
        for _ in range(self.test_iterations):
            start = time.time()
            ciphertext = rsa.encrypt(self.test_message)
            enc_times.append(time.time() - start)
            ciphertexts.append(ciphertext)
        
        # Decryption
        dec_times = []
        for ciphertext in ciphertexts:
            start = time.time()
            rsa.decrypt(ciphertext)
            dec_times.append(time.time() - start)
        
        return {
            "algorithm": "RSA",
            "key_gen_time": statistics.mean(key_gen_times),
            "encrypt_time": statistics.mean(enc_times),
            "decrypt_time": statistics.mean(dec_times),
            "ciphertext_size": len(ciphertexts[0]) if ciphertexts else 0
        }
    
    def test_elgamal(self):
        print("Testing ElGamal performance...")
        elgamal = ElGamalEncryption()
        
        # Key generation
        key_gen_times = []
        for _ in range(self.test_iterations):
            start = time.time()
            elgamal.generate_keys()
            key_gen_times.append(time.time() - start)
        
        # Encryption
        enc_times = []
        ciphertext_pairs = []
        for _ in range(self.test_iterations):
            start = time.time()
            ephemeral_public, ciphertext = elgamal.encrypt(self.test_message)
            enc_times.append(time.time() - start)
            ciphertext_pairs.append((ephemeral_public, ciphertext))
        
        # Decryption
        dec_times = []
        for ephemeral_public, ciphertext in ciphertext_pairs:
            start = time.time()
            elgamal.decrypt(ephemeral_public, ciphertext)
            dec_times.append(time.time() - start)
        
        return {
            "algorithm": "ElGamal",
            "key_gen_time": statistics.mean(key_gen_times),
            "encrypt_time": statistics.mean(enc_times),
            "decrypt_time": statistics.mean(dec_times),
            "ciphertext_size": len(ciphertext_pairs[0][1]) if ciphertext_pairs else 0
        }
    
    def test_ecc(self):
        print("Testing ECC performance...")
        ecc = ECCEncryption()
        
        # Key generation
        key_gen_times = []
        for _ in range(self.test_iterations):
            start = time.time()
            ecc.generate_keys()
            key_gen_times.append(time.time() - start)
        
        # Encryption
        enc_times = []
        ciphertext_pairs = []
        for _ in range(self.test_iterations):
            start = time.time()
            ephemeral_public, ciphertext = ecc.encrypt(self.test_message)
            enc_times.append(time.time() - start)
            ciphertext_pairs.append((ephemeral_public, ciphertext))
        
        # Decryption
        dec_times = []
        for ephemeral_public, ciphertext in ciphertext_pairs:
            start = time.time()
            ecc.decrypt(ephemeral_public, ciphertext)
            dec_times.append(time.time() - start)
        
        return {
            "algorithm": "ECC",
            "key_gen_time": statistics.mean(key_gen_times),
            "encrypt_time": statistics.mean(enc_times),
            "decrypt_time": statistics.mean(dec_times),
            "ciphertext_size": len(ciphertext_pairs[0][1]) if ciphertext_pairs else 0
        }
    
    def test_key_generation_efficiency(self):
        start_time = time.time()
        results = []
        for key_size in self.key_sizes:
            rsa = RSAEncryption(key_size=key_size)
            key_gen_times = []
            for _ in range(self.test_iterations):
                process = psutil.Process(os.getpid())
                cpu_before = process.cpu_percent(interval=None)
                start = time.time()
                rsa.generate_keys()
                end = time.time()
                cpu_after = process.cpu_percent(interval=None)
                key_gen_times.append(end - start)
                
            avg_time = statistics.mean(key_gen_times)
            std_dev = statistics.stdev(key_gen_times) if len(key_gen_times) > 1 else 0
            avg_cpu = (cpu_after - cpu_before) / self.test_iterations
            
            results.append({
                "algorithm": "RSA",
                "key_size": key_size,
                "avg_time": avg_time,
                "std_dev": std_dev,
                "avg_cpu": avg_cpu
            })
        return results

    def test_encryption_throughput(self):
        results = []
        rsa = RSAEncryption()
        public_key = rsa.public_key
        private_key = rsa.private_key

        for data_size in self.data_sizes:
            plaintext = os.urandom(data_size)
            
            # Encryption
            enc_times = []
            enc_cpu_usages = []
            for _ in range(self.test_iterations):
                process = psutil.Process(os.getpid())
                cpu_before = process.cpu_percent(interval=None)
                start = time.time()
                ciphertext = rsa.encrypt(public_key, plaintext)
                end = time.time()
                cpu_after = process.cpu_percent(interval=None)
                
                enc_times.append(end - start)
                enc_cpu_usages.append(cpu_after - cpu_before)

            # Decryption
            dec_times = []
            dec_cpu_usages = []
            for _ in range(self.test_iterations):
                process = psutil.Process(os.getpid())
                cpu_before = process.cpu_percent(interval=None)
                start = time.time()
                decrypted = rsa.decrypt(private_key, ciphertext)
                end = time.time()
                cpu_after = process.cpu_percent(interval=None)
                
                dec_times.append(end - start)
                dec_cpu_usages.append(cpu_after - cpu_before)

            results.append({
                "data_size": data_size,
                "avg_enc_time": statistics.mean(enc_times),
                "avg_enc_cpu": statistics.mean(enc_cpu_usages),
                "avg_dec_time": statistics.mean(dec_times),
                "avg_dec_cpu": statistics.mean(dec_cpu_usages)
            })
        return results

    def test_security_verification(self):
        rsa = RSAEncryption()
        rsa.generate_keypair()
        public_key = rsa.public_key
        private_key = rsa.private_key
        
        # Test OAEP padding compliance
        try:
            plaintext = b"Test message for OAEP"
            ciphertext = public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            decrypted = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            oaep_compliant = decrypted == plaintext
        except Exception as e:
            oaep_compliant = False

        # Timing attack simulation
        timing_results = []
        test_plaintexts = [b"A" * 10, b"B" * 100, b"C" * 1000]
        for plaintext in test_plaintexts:
            ciphertext = public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            start = time.time()
            private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            end = time.time()
            timing_results.append(end - start)
        
        # Use CryptoTool for verification (requires CryptoTool CLI installed)
        try:
            public_pem = rsa.get_public_key_pem()
            with open("public.pem", "wb") as f:
                f.write(public_pem)
            result = subprocess.run(["cryptool", "--verify", "public.pem"], capture_output=True, text=True)
            cryptool_verified = "valid" in result.stdout.lower()
        except Exception as e:
            cryptool_verified = False
            
        return {
            "oaep_compliant": oaep_compliant,
            "timing_results": timing_results,
            "cryptool_verified": cryptool_verified
        }

    def run_all_tests(self):
        results = []
        results.append(self.test_rsa())
        results.append(self.test_elgamal())
        results.append(self.test_ecc())
        results.append({
            "key_generation_efficiency": self.test_key_generation_efficiency()
        })
        results.append({
            "encryption_throughput": self.test_encryption_throughput()
        })
        results.append({
            "security_verification": self.test_security_verification()
        })
        return results

if __name__ == "__main__":
    tester = PerformanceTester()
    results = tester.run_all_tests()
    
    print("\nPerformance Test Results:")
    for result in results:
        print(f"\nAlgorithm: {result['algorithm']}")
        print(f"Average Key Generation Time: {result['key_gen_time']:.6f} seconds")
        print(f"Average Encryption Time: {result['encrypt_time']:.6f} seconds")
        print(f"Average Decryption Time: {result['decrypt_time']:.6f} seconds")
        print(f"Ciphertext Size: {result['ciphertext_size']} bytes")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)