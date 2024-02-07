# 作者：zhangqiang
# 时间：2023-12-5
# 描述：调用源析系统

import json
import hashlib
import random
import traceback
from pathlib import Path
import urllib
from flask import Response
from flask_restful import Resource, reqparse
import requests
requests.packages.urllib3.disable_warnings()
# from werkzeug.datastructures import FileStorage
from config import yuanxi_url, mongo_db
from common import mongo_client, logging, field_length_limit, DbGidFS
from error_code import error_code

# 写死
Authorization = "Bearer f1eca0a0a72d94deb76d18950dd9cc9e"


class YuanxiDetect(Resource):
    def post(self):
        logging.info("开始源析文件检测".center(40, "*"))

        # 验证参数
        parser = reqparse.RequestParser()
        parser.add_argument("name", type=field_length_limit(1, 50), help="项目名称，长度大于0且不大于50", required=True, location="json")
        parser.add_argument("version", type=field_length_limit(1, 20), default= str(random.random()), help="版本号，长度大于0且不大于20", required=False, location="json")
        parser.add_argument("file_path", type=str, help="文件路径", required=True, location="json")
        parser.add_argument("detectTypes", type=str, help="检测类型：1=成分分析 、2=许可证分析 、3= 基本分析 、4=代码规范检查、 5=代码漏洞检测,、6=静态代码分析、7=代码克隆检测 ；多选，用逗号拼接", required=True, location="json")
        parser.add_argument("type", type=str, default="0", choices=["0", "1", "2", "3", "4"], help="上传类型 0=压缩包、 1=git远程仓库、 2=gitlab远程仓库、3=svn仓库、4=服务器挂载目录地址", required=False, location="json")
        parser.add_argument("detectTypesExtra", type=str, default='{"isBuild":false,"checkLanguage":"C/C++","checkStandard":"misra"}',  help="检测过程中额外参数，isBuild：是否需要编译, checkLanguage: 现支持C/C++,checkStandard:支持的检测标准misra,y2038,threadsafety,cert", required=False, location="json")
        parser.add_argument("config", type=str, default='{"repository_url":"","credentials":{"username":"","password":"","access_token":""},"branch":"","tag":""}', help="type为1或者2或者3的时候的配置信息，包括仓库url和凭证 json", required=False, location="json")
        # parser.add_argument("codeFile", type=FileStorage, help="上传的项目压缩包二进制文件，当type=0时，使用此字段", required=False, trim=True, location="files")

        request_args = parser.parse_args()
        name = request_args["name"]
        version = request_args["version"]
        file_path = request_args["file_path"]
        detectTypes = request_args["detectTypes"]
        type = request_args["type"]
        detectTypesExtra = request_args["detectTypesExtra"]
        config = request_args["config"]
        # codeFile = request_args["codeFile"]

        if not Path(file_path).exists():
            logging.warning("%s is not exist" % file_path)
            return {"code": 404, "message": error_code[404]["message"]}, error_code[404]["http"]

        url = yuanxi_url + "/sca/api/ext/detect"
        headers = {"Authorization": Authorization}
        payload = {
            "name": name,
            "version": version,
            "detectTypes": detectTypes,
            "type": type,
            "detectTypesExtra": detectTypesExtra,
            "config": config
        }
        # # 前端上传固件
        # files = [
        #     ('codeFile', (codeFile.filename, codeFile.stream.read()))
        # ]

        # 前端上传固件路径
        file_name = Path(file_path).name
        file_data = Path(file_path).read_bytes()
        md5 = hashlib.md5(file_data).hexdigest()
        sha256 = hashlib.sha256(file_data).hexdigest()
        files = {
            "codeFile": (file_name, file_data, )
        }
        logging.info(payload)

        try:
            response = requests.post(url, headers=headers, files=files, data=payload, verify=False)
            resp = json.loads(response.text)
            logging.debug(f"源析文件检测的响应:{resp}")

            if resp["errno"] == 0:
                input_data = {
                    "md5": md5,
                    "sha256": sha256,
                    "file_name": file_name,
                    "file_path": file_path,
                    "name": name,
                    "version": version,
                    "detectypes": detectTypes.split(","),
                    "uploadId": resp["data"].get("uploadId")
                }
                mongo_client[mongo_db]["yuanxi_collection"].insert_one(input_data)
                return {"code": 200, "message": error_code[200]["message"], "data": {"uploadId": resp["data"].get("uploadId")}}, error_code[200]["http"]
            return {"code": resp["errno"], "message": error_code[resp["errno"]]["message"]}, error_code[resp["errno"]]["http"]
        except:
            logging.error(traceback.print_exc())
            return {"code": 400, "message": error_code[400]["message"]}, error_code[400]["http"]


class YuanxiDetectResult(Resource):
    def post(self):
        logging.info("源析文件检测结果查看".center(40, "*"))

        # 验证参数
        parser = reqparse.RequestParser()
        parser.add_argument("uploadId", type=int, help="上传检测的id", required=True, location="json")
        request_args = parser.parse_args()
        uploadId = request_args["uploadId"]

        url = yuanxi_url + "/sca/api/ext/getDetectResult"
        headers = {"Content-Type": "application/json", "Authorization": Authorization}
        payload = {
            "uploadId": uploadId
        }

        try:
            response = requests.post(url, headers=headers, json=payload, verify=False)
            resp = json.loads(response.text)
            logging.debug(f"源析文件检测结果是:{resp}")

            if resp['errno'] == 0:
                data = resp["data"]

                # 往基本分析里添加“项目名称”、“文件名称”
                result = mongo_client[mongo_db]["yuanxi_collection"].find_one({"uploadId": uploadId})
                name = result["name"] if result else ""
                file_name = result["file_name"] if result else ""
                detectList = data["detectList"]
                if detectList:
                    for i in detectList:
                        if i["algorithmType"] == 3:
                            i["algorithmResult"]["name"] = name
                            i["algorithmResult"]["file_name"] = file_name

                detectStatus_map = {1: "已完成", 0: "进行中", 2: "检测失败", 3: "上传或者解压文件失败"}
                if data["detectStatus"] != 0:   # 1=已完成、0=进行中、2=检测失败、3=上传或者解压文件失败
                    newvalues = {"detectStatus": detectStatus_map[data["detectStatus"]], "detectErr": data["detectErr"], "detectList": data["detectList"]}
                    # mongo_client[mongo_db]["yuanxi_collection"].update_one(filter={"uploadId": uploadId}, update={'$set': newvalues})

                    # 使用GridFS解决document大于16MB的限制
                    db_gridfs = DbGidFS(mongo_client, mongo_db, "yuanxi_collection")
                    db_gridfs.insert_or_update_table(uploadId, gfs_Data=newvalues)

                data["detectStatus"] = detectStatus_map[data["detectStatus"]]
                return {"code": 200, "message": error_code[200]["message"], "data": data},  error_code[200]["http"]
            return {"code": resp["errno"], "message": error_code[resp["errno"]]["message"]}, error_code[resp["errno"]]["http"]
        except:
            logging.error(traceback.print_exc())
            return {"code": 400, "message": error_code[400]["message"]}, error_code[400]["http"]


class YuanxiCodeLintShow(Resource):
    def post(self):
        logging.info("源析代码规范检查查看".center(40, "*"))

        # 验证参数
        parser = reqparse.RequestParser()
        parser.add_argument("uploadId", type=int, help="上传检测的id", required=True, location="json")
        parser.add_argument("language", type=str, help="代码语言", required=True, location="json")
        request_args = parser.parse_args()
        uploadId = request_args["uploadId"]
        language = request_args["language"]

        if not mongo_client[mongo_db]["yuanxi_collection"].find_one({"uploadId": uploadId}):
            logging.info(f"uploadId {uploadId} is not exist")
            return {"code": 500, "message": error_code[500]["message"]}, error_code[500]["http"]

        scan_url = yuanxi_url + "/sca/api/detect/codeLintShow"
        headers = {"Content-Type": "application/json", "Authorization": Authorization}
        payload = {
            "uploadId": uploadId,
            "language": language
        }

        try:
            response = requests.post(scan_url, headers=headers, json=payload, verify=False)
            resp = json.loads(response.text)
            logging.debug(f"源析代码规范检查查看结果是:{resp}")

            if resp['errno'] == 0:
                data = resp["data"]
                if data == {}:  # 统一"language参数有误"场景下返回值格式
                    data = []
                return {"code": 200, "message": error_code[200]["message"], "data": data}, error_code[200]["http"]
            return {"code": resp["errno"], "message": error_code[resp["errno"]]["message"]}, error_code[resp["errno"]]["http"]
        except:
            logging.error(traceback.print_exc())
            return {"code": 400, "message": error_code[400]["message"]}, error_code[400]["http"]


class YuanxiDownload(Resource):
    def post(self):
        logging.info("源析代码规范检查下载文件".center(40, "*"))

        # 验证参数
        parser = reqparse.RequestParser()
        parser.add_argument("file_path", type=str, help="文件路径", required=True, location="json")
        request_args = parser.parse_args()
        path = request_args["file_path"]

        url = yuanxi_url + "/sca" + path
        headers = { "Content-Type": "application/json", "Authorization": Authorization }
        filename = path.split("/")[-1]

        try:
            # 流式下载
            def send_chunk():
                with urllib.request.urlopen(url) as fp:
                    size = fp.headers['content-length']
                    # logging.info(size)
                    while True:
                        chunk = fp.read(20 * 1024 * 1024)
                        if not chunk:
                            break
                        return chunk
            return Response(response=send_chunk(), status=200, headers={"Content-Type": "application/octet-stream", "Content-Disposition": "attachment; filename=" + urllib.parse.quote(filename)})
        except urllib.error.URLError as e:
            logging.error("发生了URLError异常: ", e)
            return {"code": 400, "message": error_code[404]["message"]}, error_code[404]["http"]
        except Exception as e:
            logging.error("发生了其他异常: ", e)
            return {"code": 400, "message": error_code[400]["message"]}, error_code[400]["http"]