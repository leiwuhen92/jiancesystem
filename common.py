import pymongo
from config import mongo_ip, mongo_port
import logging
import json
import requests


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


def monitor_trans(target_url, method, body, headers):
    """
    专网与v网转换
    :return: target_url接口响应结果
    """
    data = {
        'target': target_url,
        'method': method,
        'body': body,
        'headers': headers
    }
    url = "http://192.168.11.72:10001/request"

    try:
        response = requests.post(url, json=data)
        response.raise_for_status()
        result_json = json.loads(response.text)
        return result_json['data']
    except Exception as e:
        print(f"发生未知异常：{e}")
        return


if __name__ == '__main__':
    target_url = "https://query.asilu.com/weather/baidu"
    method = 'POST'
    body = {'city': '北京'}
    headers = {
        'Content-Type': 'application/json',
    }

    print(monitor_trans(target_url, method, body, headers))
