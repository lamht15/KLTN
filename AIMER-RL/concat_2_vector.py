import os
import numpy as np

def concatenate_files(file_path1, file_path2, output_folder):
    print(file_path1)
    # Đọc dữ liệu từ file 1
    with open(file_path1, 'r') as f1:
        data1 = f1.read()
        vector1 = np.array(eval(data1))

    # Tạo tên file kết quả cho trường hợp nối file1 với chính nó
    file1_name = os.path.basename(file_path1)
    output_file1 = f"concatenated_{file1_name}_{file1_name}"

    # Nối file1 với chính nó
    concatenated_vector1 = np.concatenate((vector1, vector1))

    # Lưu kết quả vào file mới
    with open(os.path.join(output_folder, output_file1), 'w') as f1:
        f1.write(str(list(concatenated_vector1)))

    # Đọc dữ liệu từ file 2
    with open(file_path2, 'r') as f2:
        data2 = f2.read()
        vector2 = np.array(eval(data2))

    # Tạo tên file kết quả cho trường hợp nối file1 với file2
    file2_name = os.path.basename(file_path2)
    output_file2 = f"concatenated_{file1_name}_{file2_name}"

    # Nối file1 với file2
    concatenated_vector2 = np.concatenate((vector1, vector2))

    # Lưu kết quả vào file mới
    with open(os.path.join(output_folder, output_file2), 'w') as f2:
        f2.write(str(list(concatenated_vector2)))