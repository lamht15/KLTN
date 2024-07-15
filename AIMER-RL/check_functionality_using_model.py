import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing.image import load_img, img_to_array

def check_functionality(image_path):
        # Đường dẫn tới ảnh cần dự đoán
        # image_path = 'đường_dẫn_đến_ảnh_cần_dự_đoán.jpg'

        # Đọc và chuyển ảnh thành mảng numpy
        image = load_img(image_path, target_size=(32, 32))
        image_array = img_to_array(image)
        image_array = np.expand_dims(image_array, axis=0)  # Thêm chiều batch

        # Rescale ảnh
        image_array /= 255.0

        # Tải mô hình từ file
        model = tf.keras.models.load_model("C:\\Users\\thanh\\Downloads\\KLTN\\Check-Functionality\\Model3=1_.keras")

        # Dự đoán nhãn của ảnh
        prediction = model.predict(image_array)[0]

        # In ra dự đoán
        print("Dự đoán của mô hình:", prediction[0], prediction[1])
        # if(prediction[0] >= prediction[1]):
        #         return prediction[0]
        # else:
        #         return prediction[1]
        return prediction[1]