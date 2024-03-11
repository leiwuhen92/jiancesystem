import requests
import json
import re
from config import yuanxi_url
from utils.common import logging


def get_token():
    with open('config.py', 'r') as file:
        content = file.read()
        token = re.findall(r'Yuanxi_Authorization = "(.*)"', content)
    return token[0]


def check_token(Yuanxi_Authorization):
    token = Yuanxi_Authorization[7:]
    check_token_url = yuanxi_url + "/sca/api/ext/checkTokenVaild"
    payload = {"accessToken": token}
    response = requests.post(check_token_url, json=payload, verify=False)
    resp = json.loads(response.text)
    is_valid = resp['data']['isVaild']
    return is_valid


def create_token(user, pwd):
    create_token_url = yuanxi_url + "/sca/api/ext/token"
    payload = {"account_name": user, "password": pwd}
    response = requests.post(create_token_url, json=payload, verify=False)
    resp = json.loads(response.text)
    accesstoken = resp['data']['accessToken']
    return accesstoken


def write_2_py(Yuanxi_Authorization):
    with open('config.py', 'r') as file:
        lines = file.readlines()

    # 使用正则表达式找到Yuanxi_Authorization的行，并替换其值
    pattern = r'^Yuanxi_Authorization\s*=\s*["\'](.*)["\']'
    for i, line in enumerate(lines):
        match = re.match(pattern, line)
        if match:
            # 替换Yuanxi_Authorization的值
            lines[i] = f"Yuanxi_Authorization = \"Bearer {Yuanxi_Authorization}\"\n"

    # 将修改后的内容写回config.py文件
    with open('config.py', 'w') as file:
        file.writelines(lines)

    logging.info(f"yuanxi'token has been updated to {Yuanxi_Authorization} in config.py")


if __name__ == "__main__":
    token = get_token()
    is_valid = check_token(token)
    if is_valid:
        print("token is valid")
    else:
        token = create_token("yinggang@163.com", "admin@15312050521")
        print(f"new token: {token}")
        write_2_py(token)