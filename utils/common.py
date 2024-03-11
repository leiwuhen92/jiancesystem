import pymongo
from config import mongo_ip, mongo_port
import logging


mongo_client = pymongo.MongoClient(host=mongo_ip, port=mongo_port, connect=False, username="admin", password="Admin_123", authSource="admin")
logging.basicConfig(level=logging.INFO, format="[%(asctime)s][%(levelname)s][%(filename)s:%(lineno)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")


def field_length_limit(min_length, max_length):
    def validate(s):
        if type(s) != str:
            raise ValueError("The field must be String.")
        if min_length < len(s) <= max_length:
            return s
        raise ValueError("The field's length must %d-%d characters." % (min_length, max_length))

    return validate


# 将数字转换成格式化字符
def get_length_string(bytes_len):
    carry_digit = 1024
    if bytes_len < carry_digit:  # 比特
        length_string = str(round(bytes_len, 2)) + ' B' # 字节
    elif bytes_len >= carry_digit and bytes_len < carry_digit * carry_digit:
        length_string = str(round(bytes_len / carry_digit, 2)) + ' KB' # 千字节
    elif bytes_len >= carry_digit * carry_digit and bytes_len < carry_digit * carry_digit * carry_digit:
        length_string = str(round(bytes_len / carry_digit / carry_digit, 2)) + ' MB' # 兆字节
    elif bytes_len >= carry_digit * carry_digit * carry_digit and bytes_len < carry_digit * carry_digit * carry_digit * carry_digit:
        length_string = str(round(bytes_len / carry_digit / carry_digit / carry_digit, 2)) + ' GB' # 千兆字节
    elif bytes_len >= carry_digit * carry_digit * carry_digit * carry_digit and bytes_len < carry_digit * carry_digit * carry_digit * carry_digit * carry_digit:
        length_string = str(round(bytes_len / carry_digit / carry_digit / carry_digit / carry_digit, 2)) + ' TB' # 太字节
    elif bytes_len >= carry_digit * carry_digit * carry_digit * carry_digit * carry_digit and bytes_len < carry_digit * carry_digit * carry_digit * carry_digit * carry_digit * carry_digit:
        length_string = str(round(bytes_len / carry_digit / carry_digit / carry_digit / carry_digit / carry_digit, 2)) + ' PB' # 拍字节
    elif bytes_len >= carry_digit * carry_digit * carry_digit * carry_digit * carry_digit * carry_digit and bytes_len < carry_digit * carry_digit * carry_digit * carry_digit * carry_digit * carry_digit * carry_digit:
        length_string = str(round(bytes_len / carry_digit / carry_digit / carry_digit / carry_digit / carry_digit /carry_digit, 2)) + ' EB' # 艾字节
    return length_string