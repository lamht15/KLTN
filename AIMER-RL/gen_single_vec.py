import angr
import numpy as np
import hashlib
import os
import time


def convert_exe_to_vector(exe_file_path):
    # Tạo project từ tệp exe
    project = angr.Project(exe_file_path, auto_load_libs=False, load_options={})

    # Lấy địa chỉ của hàm entry point
    entry_address = project.entry

    # Tạo một đối tượng CFG từ hàm entry point
    cfg = project.analyses.CFGFast()

    # Tạo danh sách các strand
    strands = []
    for node in cfg.graph.nodes():
        block = cfg.model.get_any_node(node.addr)
        if block is not None and hasattr(block.block, 'capstone') and block.block.capstone is not None:
            strand = []
            for stmt in block.block.capstone.insns:
                # chỉnh lại format của từng câu lệnh
                expression = convert_instruction_to_expression(stmt)
                if expression:
                    strand.append(expression)
            strands.append(strand)
    #print(strands[1])

    # Tạo biểu thức từ các strand và chuẩn hóa
    expressions = []
    for strand in strands:
        expression = " ".join(strand)
        expressions.append(expression)
    print(expressions[1])
    # Băm biểu thức thành giá trị và thêm vào vectơ
    vector = [0]*2**10  # Tạo vectơ 1024 chiều
    for expression in expressions:
        md5_hash = hashlib.md5(expression.encode()).hexdigest()
        index = int(md5_hash, 16)%2**10
        vector[index] += 1
    return entry_address, vector

def convert_instruction_to_expression(instruction):
    # Lấy lệnh assembly
    assembly = instruction.mnemonic + " " + instruction.op_str
    return assembly


# Đường dẫn thư mục chứa các tệp exe cần chuyển đổi
# input_folder = "C:\\Users\\thanh\\OneDrive\\Máy tính\\Functionality\\Gen_vec_don\\Input"

# # Đường dẫn thư mục chứa các tệp văn bản đầu ra
# output_folder = "C:\\Users\\thanh\\OneDrive\\Máy tính\\Functionality\\Gen_vec_don\\Output"

# Duyệt qua tất cả các tệp trong thư mục đầu vào
def gen_vec(input_folder, output_folder):
    # Xác định đường dẫn đầy đủ của tệp exe
    exe_file_path = input_folder

    # Tạo tên tệp văn bản đầu ra từ tên tệp exe
    file_name = os.path.basename(input_folder)
    output_file_name = file_name.replace(".exe", ".txt")
    # Xác định đường dẫn đầy đủ của tệp văn bản đầu ra
    output_file_path = os.path.join(output_folder, output_file_name)

    print(f"Đang xử lý tệp {file_name}...")

    start_time = time.time()  # Bắt đầu đếm thời gian

    # Chuyển đổi tệp exe thành vectơ
    # Chuyển đổi tệp exe thành vectơ
    try:
        entry_address, result_vector = convert_exe_to_vector(exe_file_path)
    except Exception as e:
        print("An error occurred:", e)
        result_vector = None  # Gán giá trị None cho result_vector nếu có lỗi

    if result_vector is not None:
        end_time = time.time()  # Kết thúc đếm thời gian
        elapsed_time = end_time - start_time  # Thời gian đã trôi qua

    # Mở file để ghi dữ liệu
        with open(output_file_path, "w") as file:
            # Tạo chuỗi vectơ
            vector_string = "[" + ", ".join([str(value) for value in result_vector]) + "]"

            # Ghi chuỗi vectơ vào file
            file.write(vector_string)

        print(f"Đã tạo tệp {output_file_name} thành công. Thời gian: {elapsed_time} giây.")
    else:
        print("Không thể tạo tệp do lỗi xảy ra.")
