import os

def create_large_file(filename, size_gb):
    # 定义每次写入的块大小为 1 MB
    block_size = 1024 * 1024
    total_size = int(size_gb * 1024 * 1024 * 1024)  # 转换为字节，并确保为整数

    # 计算需要写入多少块
    num_blocks = total_size // block_size

    with open(filename, 'wb') as f:
        for _ in range(num_blocks):
            # 写入 1 MB 的随机数据，直到达到总大小
            f.write(os.urandom(block_size))

        # 写入最后一部分数据以达到确切的文件大小
        remaining = total_size % block_size
        if remaining > 0:
            f.write(os.urandom(remaining))

    print(f"文件 {filename} 已创建，大小为 {size_gb} GB.")

# 调用函数创建文件
create_large_file("large_test_file.bin", 3.5)
