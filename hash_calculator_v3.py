from gmssl import sm3, func
import hashlib
import os
import time
from concurrent.futures import ThreadPoolExecutor

def sm3_hash_file(file_path):
    print("sm3 start")
    with open(file_path, 'rb') as file:
        data = file.read()
        sm3_result = sm3.sm3_hash(func.bytes_to_list(data)).hex()
        print("sm3 finish")
        return sm3_result

def calculate_file_hash(filename, hash_algorithm):
    block_size = 1048576  # 1 MB

    if hash_algorithm == sm3_hash_file:
        return sm3_hash_file(filename)
    else:
        hash_obj = hash_algorithm()
        print(hash_algorithm + " start")
        with open(filename, 'rb') as file:
            for chunk in iter(lambda: file.read(block_size), b""):
                hash_obj.update(chunk)
        print(hash_algorithm + " finish")
        return hash_obj.hexdigest()


def main():
    file_path = 'large_test_file.txt'

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
