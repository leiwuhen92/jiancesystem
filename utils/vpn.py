import json
import requests
from config import vpn_url


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
    # url = "http://192.168.11.72:10001/request"

    try:
        response = requests.post(vpn_url, json=data)
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
