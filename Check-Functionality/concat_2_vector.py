import os
import numpy as np

# Đường dẫn đến thư mục chứa các file
folder_path = "/content/gdrive/MyDrive/KLTN/2vector"

# Đường dẫn đến thư mục lưu kết quả
output_folder = "/content/gdrive/MyDrive/KLTN/Check"

# Kiểm tra xem thư mục lưu kết quả có tồn tại chưa, nếu chưa thì tạo mới
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

# Lấy danh sách các file trong thư mục
files = os.listdir(folder_path)

# Lặp qua từng file trong thư mục
for file1 in files:
    # Đọc dữ liệu từ file 1
    with open(os.path.join(folder_path, file1), 'r') as f1:
        data1 = f1.read()
        vector1 = np.array(eval(data1))

    # Tạo tên file kết quả cho trường hợp nối file1 với chính nó
    output_file1 = f"concatenated_{file1}_{file1}"

    # Nối file1 với chính nó
    concatenated_vector1 = np.concatenate((vector1, vector1))

    # Lưu kết quả vào file mới
    with open(os.path.join(output_folder, output_file1), 'w') as f1:
        f1.write(str(list(concatenated_vector1)))

    # Lặp qua từng file trong thư mục một lần nữa để nối file1 với các file khác
    for file2 in files:
        if file1 != file2:
            # Đọc dữ liệu từ file 2
            with open(os.path.join(folder_path, file2), 'r') as f2:
                data2 = f2.read()
                vector2 = np.array(eval(data2))

            # Tạo tên file kết quả cho trường hợp nối file1 với file2
            output_file2 = f"concatenated_{file1}_{file2}"

            # Nối file1 với file2
            concatenated_vector2 = np.concatenate((vector1, vector2))

            # Lưu kết quả vào file mới
            with open(os.path.join(output_folder, output_file2), 'w') as f2:
                f2.write(str(list(concatenated_vector2)))