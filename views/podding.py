# 作者：zhangqiang
# 时间：2023-12-5
# 描述：调用podding系统

import json
import pathlib
import time
import hashlib
import traceback
from flask_restful import Resource, reqparse
import requests
requests.packages.urllib3.disable_warnings()
from config import podding_url, mongo_db, Podding_Authorization
from utils.common import mongo_client, logging
from error_code import error_code


def upload_precheck(file_path, access_token_headers):
    url = podding_url + "/api/upload_precheck"
    file_path_pathlib = pathlib.Path(file_path)
    file_data = file_path_pathlib.read_bytes()
    sha256 = hashlib.sha256(file_data).hexdigest()
    requests_data = {"name": file_path_pathlib.name, "size": len(file_data), "sha-256": sha256}
    response = requests.post(url, data=json.dumps(requests_data), headers=access_token_headers, verify=False)
    resp = json.loads(response.text)

    logging.info(f"upload precheck api response:{resp}")
    return resp, response.status_code, sha256


def upload(file_path, multipart_headers):
    url = podding_url + "/api/upload"
    file_path_pathlib = pathlib.Path(file_path)
    name = file_path_pathlib.name
    file_data = file_path_pathlib.read_bytes()
    totalSize = len(file_data)
    chunkSize = 2048000
    identifier_temp = str(format(time.time(), ".3f")).replace(".", "")
    identifier = identifier_temp + "_" + name
    totalChunks = int(totalSize/chunkSize) + 1
    # 数据大小大于chunkSize大小
    if totalSize > chunkSize:
        # 完整chunkSize
        for i in range(0, totalChunks - 1):
            # 设置数据
            chunkNumber = i + 1
            currentChunkSize = chunkSize
            file = file_data[i * chunkSize : (i+1) * chunkSize]
            # 构造数据
            files = {"chunkNumber" : (None, chunkNumber),"chunkSize" : (None, chunkSize),"currentChunkSize" : (None, currentChunkSize),"totalSize" : (None, totalSize),"identifier" : (None, identifier),"totalChunks" : (None,totalChunks),"file" : (name, file)}
            # upload
            requests.post(url, files=files, headers=multipart_headers, verify=False)

        # 最后的数据
        # 设置数据
        chunkNumber = totalChunks
        currentChunkSize = totalSize - (chunkSize * (totalChunks-1))
        file = file_data[chunkSize * (totalChunks-1) : totalSize]
        # 构造数据
        files = {"chunkNumber" : (None, chunkNumber),"chunkSize" : (None, chunkSize),"currentChunkSize" : (None, currentChunkSize),"totalSize" : (None, totalSize),"identifier" : (None, identifier),"totalChunks" : (None,totalChunks),"file": (name, file),}
        # upload
        response = requests.post(url, files=files, headers=multipart_headers, verify=False)
        resp = json.loads(response.text)
        if resp['code'] != 0:
            logging.error(f"upload {name} error:{resp['message']}")
            return identifier, response.status_code, resp
    else:
        # 设置数据
        chunkNumber = 1
        currentChunkSize = totalSize
        file = file_data
        # 构造数据
        files = {"chunkNumber" : (None, chunkNumber),"chunkSize" : (None, chunkSize),"currentChunkSize" : (None, currentChunkSize),"totalSize" : (None, totalSize),"identifier" : (None, identifier),"totalChunks" : (None,totalChunks),"file" : (name, file),}
        # upload
        response = requests.post(url, files=files, headers=multipart_headers, verify=False)
        resp = json.loads(response.text)
        if resp['code'] != 0:
            logging.error(f"upload {name} error:{resp['message']}")
            return identifier, response.status_code, resp

    logging.info(f"identifier:{identifier}, upload api response:{resp}")
    return identifier, 200, resp


def add_task(identifier, name, access_token_headers):
    url = podding_url + "/api/add_task"
    file_list = [identifier]
    requests_data = {"name": name, "file": file_list}
    response = requests.post(url, data=json.dumps(requests_data), headers=access_token_headers, verify=False)
    resp = json.loads(response.text)

    logging.info(f"add task response:{resp}")
    return resp, response.status_code


class PoddingAnalysis(Resource):
    def post(self):
        logging.info("in podding analysis".center(40, "*"))

        # 验证参数
        parser = reqparse.RequestParser()
        parser.add_argument("file_path", type=str, help="文件路径", required=True, location="json")
        parser.add_argument("name", type=str, help="任务名称", required=True, location="json")
        request_args = parser.parse_args()
        file_path = request_args["file_path"]
        name = request_args["name"]
        logging.info(f"name:{name}")

        # 判断文件是否存在
        if not pathlib.Path(file_path).exists():
            logging.warning(f"{file_path} is not exist")
            return {"code": 404, "message": error_code[404]["message"]}, error_code[404]["http"]

        file_name = pathlib.Path(file_path).name
        file_data = pathlib.Path(file_path).read_bytes()
        md5 = hashlib.md5(file_data).hexdigest()
        sha256 = hashlib.sha256(file_data).hexdigest()

        access_token_headers = {"content-type": "application/json", "Accept": "application/json", "Authorization": Podding_Authorization}
        multipart_headers = {"Authorization": Podding_Authorization}

        try:
            resp1, status_code_1, sha256 = upload_precheck(file_path, access_token_headers)
            if resp1['code'] == 0:
                exist = resp1['data']['exist']
                if exist == 1:
                    identifier = sha256
                else:
                    identifier, status_code_2, resp2 = upload(file_path, multipart_headers)
                    if status_code_2 != 200:
                        return {"code": status_code_2, "message": resp2["message"]}, status_code_2

                resp3, status_code_3 = add_task(identifier, name, access_token_headers)
                if resp3['code'] == 0:
                    input_data = {
                        "md5": md5,
                        "sha256": sha256,
                        "file_name": file_name,
                        "file_path": file_path,
                        "taskid": resp3["data"]["id"],
                        "taskname": name
                    }
                    mongo_client[mongo_db]["podding_collection"].update_one(filter={"md5": md5}, update={'$set': input_data}, upsert=True)
                    return {"code": 200, "message": error_code[200]["message"], "data": {"task_id": resp3["data"]["id"], "id": sha256}}, error_code[200]["http"]
                return {"code": resp3["code"], "message": resp3["message"]}, status_code_3
            return {"code": resp1["code"], "message": resp1["message"]}, status_code_1
        except:
            logging.error(traceback.print_exc())
            return {"code": 400, "message": error_code[400]["message"]}, error_code[400]["http"]


class PoddingSearchOption(Resource):
    def get(self):
        logging.info("in podding get search option".center(40, "*"))

        headers = {"content-type": "application/json", "Authorization": Podding_Authorization}
        url = podding_url + "/api/firmware_search_option"

        try:
            response = requests.get(url, headers=headers, verify=False)
            resp = json.loads(response.text)
            logging.debug(f"podding搜索项的响应:{resp}")

            if resp["code"] == 0:
                return {"code": 200, "message": error_code[200]["message"], "data": resp["data"]}, error_code[200]["http"]
            return {"code": resp["code"], "message": resp["message"]}, response.status_code
        except:
            logging.error(traceback.print_exc())
            return {"code": 400, "message": error_code[400]["message"]}, error_code[400]["http"]


class PoddingSearch(Resource):
    def post(self):
        logging.info("in podding search firmware".center(40, "*"))

        parser = reqparse.RequestParser()
        parser.add_argument("page_num", type=int, help="当前页数", required=True, location="json")
        parser.add_argument("page_size", type=int, default=10, help="每页条数", required=False, location="json")
        parser.add_argument("id", type=str, help="固件ID", required=False, trim=True, location="json")
        parser.add_argument("md5", type=str, help="固件md5", required=False, trim=True, location="json")
        parser.add_argument("name", type=str, help="固件名称", required=False, trim=True, location="json")
        parser.add_argument("vendor", type=str, action='append', help="固件的厂商列表", required=False, trim=True, location="json")
        parser.add_argument("start_size", type=int, help="开始大小", required=False, location="json")
        parser.add_argument("end_size", type=int, help="结束大小", required=False, location="json")
        parser.add_argument("device_type", type=str, action='append', help="设备类型列表", required=False, trim=True, location="json")
        parser.add_argument("product", type=str, help="设备型号", required=False, trim=True, location="json")
        parser.add_argument("component", type=str, action='append', help="软件成分（组件列表）", required=False, trim=True, location="json")
        parser.add_argument("advanced_search", type=dict, help="错误的请求", location="json")

        request_args = parser.parse_args()
        page_num = request_args["page_num"]
        page_size = request_args["page_size"]
        firmware_id = request_args["id"]
        firmware_md5 = request_args["md5"]
        firmware_name = request_args["name"]
        vendor_list = request_args["vendor"]
        start_size = request_args["start_size"]
        end_size = request_args["end_size"]
        device_type_list = request_args["device_type"]
        product = request_args["product"]
        component_list = request_args["component"]
        advanced_search = request_args["advanced_search"]

        headers = {"content-type": "application/json", "Authorization": Podding_Authorization}
        url = podding_url + "/api/firmware_summary"
        data ={
            "page_num": page_num,
            "page_size": page_size,
            "advanced_search": advanced_search
        }
        if firmware_id: data["id"] = firmware_id
        if firmware_md5: data["md5"] = firmware_md5
        if firmware_name: data["name"] = firmware_name
        if start_size: data["start_size"] = start_size
        if end_size: data["end_size"] = end_size
        if vendor_list: advanced_search["vendor"] = vendor_list
        if device_type_list: advanced_search["device_type"] = device_type_list
        if component_list: advanced_search["component"] = component_list
        if product: advanced_search["product"] = product

        try:
            logging.info(f"请求参数：{data}")
            response = requests.post(url, headers=headers, json=data, verify=False)
            resp = json.loads(response.text)
            logging.info(f"podding固件检索的响应:{resp}")

            firmware_list = []
            # 信息不足，再调用固件详情接口补足其他信息
            if resp["code"] == 0:
                detail_url = podding_url + "/api/firmware_detail"
                for onefirm in resp["data"]["firmware"]:
                    id = onefirm["id"]
                    data = {"id": id}
                    response = requests.post(detail_url, headers=headers, json=data, verify=False)
                    resp2 = json.loads(response.text)
                    logging.debug(resp2)

                    firm_info = {
                        "analysis_status": resp2["data"]["analysis_status"],
                        "size": onefirm["size"],
                        "mime": resp2["data"]["mime"],
                        "metadata": resp2["data"]["metadata"],
                        "decrypt_status": onefirm["decrypt_status"],
                        "vendor": resp2["data"]["vendor"],
                        "product": resp2["data"]["product"],
                        "device_type": resp2["data"]["device_type"],
                        "cve": resp2["data"]["cve"],
                        "rootfs_type": resp2["data"]["rootfs_type"],
                        "architecture": resp2["data"]["architecture"],
                        "backdoor": resp2["data"]["backdoor"],
                        "black_ip": resp2["data"]["black_ip"],
                        "buffer_overflow": resp2["data"]["buffer_overflow"],
                        "common_password": resp2["data"]["common_password"],
                        "component": resp2["data"]["component"],
                        "cve_component": resp2["data"]["cve_component"],
                        "encryption_key": resp2["data"]["encryption_key"],
                        "malware": resp2["data"]["malware"],
                        "misconfiguration": resp2["data"]["misconfiguration"],
                        "null_pointer": resp2["data"]["null_pointer"],
                        "ssl_certificate": resp2["data"]["ssl_certificate"],
                        "user_data": resp2["data"]["user_data"],
                        "username_password": resp2["data"]["username_password"]
                    }
                    other_firm_info = {
                        "id": id,
                        "name": onefirm["name"],
                        "md5": resp2["data"]["md5"],
                        "task_name": onefirm["task_name"],
                        "start_time": onefirm["start_time"],
                        "cost_time": resp2["data"]["cost_time"],
                        "vuln": onefirm["vuln"]
                    }

                    if resp2['data']["analysis_status"] != "分析中":
                        mongo_client[mongo_db]["podding_collection"].update_one(filter={"sha256": id},  update={'$set': firm_info})

                    other_firm_info.update(firm_info)
                    firmware_list.append(other_firm_info)

                response_data = {
                    "total": resp["data"]["total"],
                    "page_num": resp["data"]["page_num"],
                    "firmware": firmware_list
                }
                return {"code": 200, "message": error_code[200]["message"], "data": response_data}, error_code[200]["http"]
            return resp
        except:
            logging.error(traceback.print_exc())
            return {"code": 400, "message": error_code[400]["message"]}, error_code[400]["http"]


class PoddingFirmDetail(Resource):
    def post(self):
        logging.info("in podding get result".center(40, "*"))

        # 验证参数
        parser = reqparse.RequestParser()
        parser.add_argument("sha256", type=str, help="sha256 value", required=True, trim=True, location="json")
        request_args = parser.parse_args()
        sha256 = request_args["sha256"]

        headers = {"content-type": "application/json", "Authorization": Podding_Authorization}
        url = podding_url + "/api/firmware_detail"
        data = {"id": sha256}

        try:
            response = requests.post(url, headers=headers, json=data, verify=False)
            resp = json.loads(response.text)
            logging.debug(f"podding固件详情的响应: {resp}")

            if resp['code'] == 0:
                data = resp['data']
                if data["analysis_status"] != "分析中":
                    newvalues = {
                        "analysis_status": data["analysis_status"],
                        "size": data["size"],
                        "mime": data["mime"],
                        "metadata": data["metadata"],
                        "vendor": data["vendor"],
                        "product": data["product"],
                        "device_type": data["device_type"],
                        "cve": data["cve"],
                        "rootfs_type": data["rootfs_type"],
                        "architecture": data["architecture"],
                        "backdoor": data["backdoor"],
                        "black_ip": data["black_ip"],
                        "buffer_overflow": data["buffer_overflow"],
                        "common_password": data["common_password"],
                        "component": data["component"],
                        "cve_component": data["cve_component"],
                        "encryption_key": data["encryption_key"],
                        "malware": data["malware"],
                        "misconfiguration": data["misconfiguration"],
                        "null_pointer": data["null_pointer"],
                        "ssl_certificate": data["ssl_certificate"],
                        "user_data": data["user_data"],
                        "username_password": data["username_password"]
                    }
                    mongo_client[mongo_db]["podding_collection"].update_one(filter={"sha256": sha256}, update={'$set': newvalues})
                return {"code": 200, "message": error_code[200]["message"], "data": data}, error_code[200]["http"]
            return {"code": resp["code"], "message": resp["message"]}, response.status_code
        except:
            logging.error(traceback.print_exc())
            return {"code": 400, "message": error_code[400]["message"]}, error_code[400]["http"]


class PoddingSimilar(Resource):
    def post(self):
        logging.info("in podding similar".center(40, "*"))

        # 验证参数
        parser = reqparse.RequestParser()
        parser.add_argument("id", type=str, help="sha256 value", required=True, trim=True, location="json")
        request_args = parser.parse_args()
        sha256 = request_args["id"]

        headers = {"content-type": "application/json", "Authorization": Podding_Authorization}
        url = podding_url + "/api/firmware_similar"
        data = {"id": sha256}

        try:
            response = requests.post(url, headers=headers, json=data, verify=False)
            resp = json.loads(response.text)
            # logging.debug(f"文件相似检测的响应:{resp}")

            if resp['code'] == 0:
                return {"code": 200, "message": error_code[200]["message"], "data": resp["data"]}, response.status_code
            return {"code": resp["code"], "message": resp["message"]}, response.status_code
        except:
            logging.error(traceback.print_exc())
            return {"code": 400, "message": error_code[400]["message"]}, error_code[400]["http"]


class PoddingVulGraph(Resource):
    @staticmethod
    def format_data(data):
        logging.debug("************malware***************")
        malware = []
        tmp_malware = {}
        for i in data["malware"]:
            vuln = i["name"]
            if i["file_name"] not in tmp_malware:
                tmp_malware[i["file_name"]] = [vuln]
            else:
                if vuln not in tmp_malware[i["file_name"]]:
                    tmp_malware[i["file_name"]].append(vuln)
        for k, v in tmp_malware.items():
            malware.append({"file": k, "result": v})
        logging.debug(f"malware: {malware}")

        logging.debug("************encryption_key**************")
        encryption_key = []
        tmp_encryption_key = {}
        for i in data["encryption_key"]:
            vuln = i["name"]
            if i["file_name"] not in tmp_encryption_key:
                tmp_encryption_key[i["file_name"]] = [vuln]
            else:
                if vuln not in tmp_encryption_key[i["file_name"]]:
                    tmp_encryption_key[i["file_name"]].append(vuln)
        for k, v in tmp_encryption_key.items():
            encryption_key.append({"file": k, "result": v})
        logging.debug(f"encryption_key: {encryption_key}")

        logging.debug("***********common_password***************")
        common_password = []
        tmp_common_password = {}
        for i in data["common_password"]:
            vuln = {"name": i["name"], "password": i["password"]}
            if i["file_name"] not in tmp_common_password:
                tmp_common_password[i["file_name"]] = [vuln]
            else:
                if vuln not in tmp_common_password[i["file_name"]]:
                    tmp_common_password[i["file_name"]].append(vuln)
        for k, v in tmp_common_password.items():
            common_password.append({"file": k, "result": v})
        logging.debug(f"common_password: {common_password}")

        logging.debug("**************backdoor*********************")
        backdoor = []
        tmp_backdoor = {}
        for i in data["backdoor"]:
            vuln = {"name": i["name"], "description": i["description"]}
            if i["file_name"] not in tmp_backdoor:
                tmp_backdoor[i["file_name"]] = [vuln]
            else:
                if vuln not in tmp_backdoor[i["file_name"]]:
                    tmp_backdoor[i["file_name"]].append(vuln)
        for k, v in tmp_backdoor.items():
            backdoor.append({"file": k, "result": v})
        logging.debug(f"backdoor: {backdoor}")

        logging.debug("**************black_ip*********************")
        black_ip = []
        tmp_black_ip = {}
        for i in data["black_ip"]:
            vuln = {"ip": i["name"], "country": i["country"], "category": i["category"]}
            if i["file_name"] not in tmp_black_ip:
                tmp_black_ip[i["file_name"]] = [vuln]
            else:
                if vuln not in tmp_black_ip[i["file_name"]]:
                    tmp_black_ip[i["file_name"]].append(vuln)
        for k, v in tmp_black_ip.items():
            black_ip.append({"file": k, "result": v})
        logging.debug(f"black_ip: {black_ip}")

        logging.debug("**************misconfiguration*********************")
        misconfiguration = []
        tmp_misconfiguration = {}
        for i in data["misconfiguration"]:
            vuln = {"name": i["name"], "description": i["description"]}
            if i["type"] not in tmp_misconfiguration:
                tmp_misconfiguration[i["type"]] = [vuln]
            else:
                if vuln not in tmp_misconfiguration[i["type"]]:
                    tmp_misconfiguration[i["type"]].append(vuln)
        for k, v in tmp_misconfiguration.items():
            misconfiguration.append({"type": k, "file": v})
        logging.debug(f"misconfiguration: {misconfiguration}")

        logging.debug("**************cwe*********************")
        cwe = []
        tmp_cwe = {}
        for i in data["buffer_overflow"] + data["null_pointer"]:
            vuln = {"name": i["name"], "description": i["description"]}
            if i["file_name"] not in tmp_cwe:
                tmp_cwe[i["file_name"]] = [vuln]
            else:
                if vuln not in tmp_cwe[i["file_name"]]:
                    tmp_cwe[i["file_name"]].append(vuln)
        for k, v in tmp_cwe.items():
            cwe.append({"file_name": k, "result": v})
        logging.debug(f"cwe: {cwe}")

        logging.debug("**************cve_component*********************")
        cve_component = []
        tmp_cve_component = {}
        for i in data["cve_component"]:
            component = i["name"] + i["version"]
            cve = i["cve"]
            for m in range(len(cve)):
                for n in data["cve_patch"]:
                    if cve[m]["id"] == n["name"]:
                        cve[m]["describe"] = n.get("description", "")
                        cve[m]["link"] = n.get("link", "")

            vuln = {"file": i["file_name"], "cve": cve}
            if component not in tmp_cve_component:
                tmp_cve_component[component] = [vuln]
            else:
                for j in range(len(tmp_cve_component[component])):
                    if vuln["file"] == tmp_cve_component[component][j]["file"]:
                        tmp_cve_component[component][j]["cve"].extend(vuln["cve"])
                    else:
                        tmp_cve_component[component][j]["cve"] = vuln["cve"]
        for k, v in tmp_cve_component.items():
            cve_component.append({"component": k, "result": v})
        logging.debug(f"cve_component: {cve_component}")

        return cve_component, common_password, backdoor, cwe, encryption_key, malware, misconfiguration, black_ip

    def post(self):
        logging.info("in podding vul graph".center(40, "*"))

        # 验证参数
        parser = reqparse.RequestParser()
        parser.add_argument("id", type=str, help="sha256 value", required=True, trim=True, location="json")
        request_args = parser.parse_args()
        sha256 = request_args["id"]

        headers = {"content-type": "application/json", "Authorization": Podding_Authorization}
        url = podding_url + "/api/firmware_vuln"
        data = {"id": sha256}

        try:
            response = requests.post(url, headers=headers, json=data, verify=False)
            resp = json.loads(response.text)
            logging.debug("固件漏洞的响应:%s" % resp)

            if resp['code'] == 0:
                cve_component, common_password, backdoor, cwe, encryption_key, malware, misconfiguration, black_ip = self.format_data(resp["data"])
                graph_data = {
                    "id": sha256,
                    "name": "",
                    "cve_component": cve_component,
                    "common_password": common_password,
                    "backdoor": backdoor,
                    "cwe": cwe,
                    "encryption_key": encryption_key,
                    "malware": malware,
                    "configure": misconfiguration,
                    "blackip": black_ip
                }
                return {"code": 200, "message": error_code[200]["message"], "data": graph_data}, response.status_code
            return {"code": resp["code"], "message": resp["message"]}, response.status_code
        except:
            logging.error(traceback.print_exc())
            return {"code": 400, "message": error_code[400]["message"]}, error_code[400]["http"]