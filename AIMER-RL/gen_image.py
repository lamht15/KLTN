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


def gen_image(file_name, folder_path, output_folder):
    image_shape = (32, 32, 2)  # Set kích thước cho hình ảnh (2x1024)
    vector_file = folder_path
    print("Filename:" + file_name)
    vector_array = read_vector_from_txt(vector_file)

    for i, vector in enumerate(vector_array):
        print(vector)
        output_image_path = os.path.join(output_folder, f"{file_name}.jpg")
        try:
            vector_to_image(vector, output_image_path, image_shape)
        except Exception as e:
            print(e)
