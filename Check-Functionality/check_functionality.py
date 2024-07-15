import os
import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing.image import ImageDataGenerator

# Thiết lập đường dẫn đến thư mục chứa dữ liệu test
test_dir = 'E:\\CNN\\Tập ảnh đã chồng - Copy\\Test'

# Tạo generator dữ liệu cho tập test
test_datagen = ImageDataGenerator(rescale=1.0/255)
test_generator = test_datagen.flow_from_directory(
        test_dir,
        target_size=(32, 32),
        batch_size=32,
        class_mode='categorical',
        shuffle=False)  # Đảm bảo generator không pha trộn dữ liệu để so sánh với nhãn

# Tải mô hình từ file
model = tf.keras.models.load_model("E:\Train_model\Model_anh_chong.h5")

# Dự đoán nhãn cho tập test
predictions = model.predict(test_generator)

# Lấy các tên file và nhãn thực tế trong tập test
file_names = test_generator.filenames
true_labels = test_generator.classes

# In ra thông tin cho 10 ảnh có nhãn 0 và 3 ảnh có nhãn 1
count_label_0, count_label_1 = 0, 0
for i, (file_name, true_label, prediction) in enumerate(zip(file_names, true_labels, predictions)):
    if count_label_0 < 10 and true_label == 0:  # Nhãn 0
        print("Tên file:", file_name)
        print("Nhãn thực tế:", true_label)
        print("Dự đoán của mô hình:", prediction[0], prediction[1])
        print()
        count_label_0 += 1
    elif count_label_1 < 10 and true_label == 1:  # Nhãn 1
        print("Tên file:", file_name)
        print("Nhãn thực tế:", true_label)
        print("Dự đoán của mô hình:", prediction[0], prediction[1])
        print()
        count_label_1 += 1
    if count_label_0 == 10 and count_label_1 == 10:  # Đã đủ 3 tên file có nhãn 0 và 3 tên file có nhãn 1
        break