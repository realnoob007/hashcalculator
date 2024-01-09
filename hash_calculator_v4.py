import hashlib
import os
import time
from concurrent.futures import ThreadPoolExecutor

class SM3Context:
    def __init__(self):
        self.state = [int(x, 16) for x in self.IV.split()]
        self.buf = bytearray()
        self.compressed_len = 0  # in bits

    IV = "7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e"
    T = [0x79cc4519 if i < 16 else 0x7a879d8a for i in range(64)]

    def P0(self, x):
        return x ^ self.left_rotate(x, 9) ^ self.left_rotate(x, 17)

    def P1(self, x):
        return x ^ self.left_rotate(x, 15) ^ self.left_rotate(x, 23)

    def FF(self, x, y, z, j):
        return x ^ y ^ z if j < 16 else (x & y) | (x & z) | (y & z)

    def GG(self, x, y, z, j):
        return x ^ y ^ z if j < 16 else (x & y) | (~x & z)

    def left_rotate(self, x, n, bits=32):
        mask = (1 << bits) - 1
        x &= mask
        return ((x << n) | (x >> (bits - n))) & mask

    def CF(self, V, B):
        W = [int.from_bytes(B[i * 4:(i + 1) * 4], byteorder='big') for i in range(16)]
        for j in range(16, 68):
            W.append(self.P1(W[j - 16] ^ W[j - 9] ^ self.left_rotate(W[j - 3], 15)) ^ self.left_rotate(W[j - 13], 7) ^ W[j - 6])
        W_ = [W[j] ^ W[j + 4] for j in range(64)]

        A, B, C, D, E, F, G, H = V
        for j in range(64):
            SS1 = self.left_rotate((self.left_rotate(A, 12) + E + self.left_rotate(self.T[j], j % 32)) & 0xffffffff, 7)
            SS2 = SS1 ^ self.left_rotate(A, 12)
            TT1 = (self.FF(A, B, C, j) + D + SS2 + W_[j]) & 0xffffffff
            TT2 = (self.GG(E, F, G, j) + H + SS1 + W[j]) & 0xffffffff
            D = C
            C = self.left_rotate(B, 9)
            B = A
            A = TT1
            H = G
            G = self.left_rotate(F, 19)
            F = E
            E = self.P0(TT2)

        return [a ^ b for a, b in zip(V, [A, B, C, D, E, F, G, H])]

    def update(self, msg):
        self.buf += msg
        while len(self.buf) >= 64:
            self.state = self.CF(self.state, self.buf[:64])
            self.buf = self.buf[64:]
            self.compressed_len += 512

    def done(self):
        msg_len = (self.compressed_len + len(self.buf) * 8).to_bytes(8, byteorder='big')
        self.update(b'\x80' + b'\x00' * ((119 - len(self.buf)) % 64) + msg_len)
        return ''.join(['{:08x}'.format(x) for x in self.state])

def sm3_hash_file(file_path):
    print("sm3 start")
    ctx = SM3Context()
    block_size = 1048576  # 1 MB

    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(block_size), b""):
            ctx.update(chunk)
    
    sm3_result = ctx.done()
    print("sm3 finish")
    return sm3_result

def calculate_file_hash(filename, hash_algorithm):
    block_size = 1048576  # 1 MB

    if hash_algorithm == sm3_hash_file:
        return sm3_hash_file(filename)
    else:
        hash_obj = hash_algorithm()
        print(f"{hash_algorithm.__name__} start")
        with open(filename, 'rb') as file:
            for chunk in iter(lambda: file.read(block_size), b""):
                hash_obj.update(chunk)
        print(f"{hash_algorithm.__name__} finish")
        return hash_obj.hexdigest()


def main():
    file_path = 'large_test_file.bin'

    if not os.path.exists(file_path):
        return "请检查文件路径"

    algorithms = {
        'md5': hashlib.md5,
        'sha3_256': hashlib.sha3_256,
        'sm3': sm3_hash_file
    }

    total_times = {name: 0 for name in algorithms}
    hash_values = {name: [] for name in algorithms}

    with ThreadPoolExecutor(max_workers=len(algorithms)) as executor:
        futures = {}
        for name, alg in algorithms.items():
            start_time = time.time()
            future = executor.submit(calculate_file_hash, file_path, alg)
            futures[future] = (name, start_time)

        for future in futures:
            name, start_time = futures[future]
            hash_value = future.result()
            total_time = time.time() - start_time
            total_times[name] += total_time
            hash_values[name].append(hash_value)

    average_times = {name: total_time / len(hash_values[name]) for name, total_time in total_times.items()}

    return total_times, average_times, hash_values

results = main()

with open("hash_results.txt", "w") as file:
    for algorithm, total_time in results[0].items():
        avg_time = results[1][algorithm]
        hashes = results[2][algorithm]
        output = f"algorithm name: {algorithm}\ntotal time: {total_time:.2f} seconds\naverage time: {avg_time:.4f} seconds\n"
        output += f"hash value: {hashes[0]}\n\n"
        print(output)
        file.write(output)

print("结果已保存到 hash_results.txt")