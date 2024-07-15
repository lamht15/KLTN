import cv2
import numpy as np
import re
import os

def vector_to_image(vector, output_image_path, image_shape):

    # Chia vector thành 2 ma trận 32x64
    image_channels = np.split(vector, 2)

    # Chuyển đổi mỗi ma trận thành ảnh 32x32
    image = np.stack([channel.reshape((32, 32)) for channel in image_channels], axis=-1)
    image = np.concatenate((image, image[:, :, 0:1]), axis=2)
    # Chuyển đổi kiểu dữ liệu sang uint8
    image = image.astype(np.uint8)
    # Tạo ảnh xám từ mảng ảnh
    gray_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # Lưu mảng thành ảnh
    cv2.imwrite(output_image_path, gray_image)


def read_vector_from_txt(txt_file):
    with open(txt_file, 'r') as file:
        content = file.readlines()
        vectors = []
        for line in content:
            # Lọc vector
            numbers = [float(num) for num in re.findall(r'\d+', line)]
            vectors.append(numbers)
        vector_array = np.array(vectors)
    return vector_array


if __name__ == "__main__":
    folder_path = "C:\\Users\\thanh\OneDrive\\Máy tính\\Enhi Phen\\VirusShare_cd7cea2165d14410e6ede0af8a2fc6bf\\1_m.exe"
    output_folder = "C:\\Users\\thanh\OneDrive\\Máy tính\\Enhi Phen\\VirusShare_cd7cea2165d14410e6ede0af8a2fc6bf\\Output"  # Thư mục để lưu ảnh
    os.makedirs(output_folder, exist_ok=True)  # Tạo thư mục nếu chưa tồn tại

    image_shape = (32, 32, 2)  # Set kích thước cho hình ảnh (2x1024)

    for file_name in os.listdir(folder_path):
        if file_name.endswith('.txt'):
            vector_file = os.path.join(folder_path, file_name)
            print("Filename:" + file_name)
            vector_array = read_vector_from_txt(vector_file)

            for i, vector in enumerate(vector_array):
                print(vector)
                output_image_path = os.path.join(output_folder, f"{file_name}_IMG{i + 1}.jpg")
                try:
                 vector_to_image(vector, output_image_path, image_shape)
                except Exception as e:
                    print(e)
