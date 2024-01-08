from gmssl import sm3
import hashlib
import os
import time

def sm3_hash(message: str):
    msg_list = [i for i in bytes(message.encode('UTF-8'))]
    hash_hex = sm3.sm3_hash(msg_list)
    return hash_hex

def sm3_hash_blocks(file_path):
    block_size = 4096  # 4 KB
    hash_blocks = []

    with open(file_path, 'rb') as file:
        while True:
            data = file.read(block_size)
            if not data:
                break
            hash_blocks.append(sm3_hash(data.decode('utf-8', errors='ignore')))

    combined_hash = ''.join(hash_blocks)
    return sm3_hash(combined_hash)

def calculate_file_hash(filename, hash_algorithm):
    if hash_algorithm == sm3_hash:
        return sm3_hash_blocks(filename)
    else:
        hash_obj = hash_algorithm()
        with open(filename, 'rb') as file:
            for chunk in iter(lambda: file.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

def main():
    file_path = 'large_test_file.bin'  # file path

    if not os.path.exists(file_path):
        return "请检查文件路径"

    algorithms = {
        'md5': hashlib.md5,
        'sha3_256': hashlib.sha3_256,
        'sm3': sm3_hash
    }

    num_iterations = 100
    total_times = {name: 0 for name in algorithms}
    hash_values = {name: [] for name in algorithms}

    for _ in range(num_iterations):
        for name, alg in algorithms.items():
            start_time = time.time()
            hash_value = calculate_file_hash(file_path, alg)
            total_times[name] += time.time() - start_time
            hash_values[name].append(hash_value)

    average_times = {name: total_time / num_iterations for name, total_time in total_times.items()}

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