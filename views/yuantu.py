# 作者：zhangqiang
# 时间：2023-12-6
# 描述：调用源图系统

import json
import traceback
from flask_restful import Resource, reqparse
import requests
requests.packages.urllib3.disable_warnings()
from config import yuantu_url, mongo_db, Yuanu_Usertoken
from utils.common import mongo_client, logging
from utils.vpn import monitor_trans
from error_code import error_code


class YuantuSearchNode(Resource):
    def post(self):
        """
        查询软件包
        :return:
        """
        logging.info("源图查询软件包".center(40, "*"))

        # 验证参数
        parser = reqparse.RequestParser()
        parser.add_argument("keyword", type=str, default="node_keyword", help="软件包查询关键字", required=False, location="json")
        parser.add_argument("name", type=str, help="软件包名称", required=True, location="json")
        parser.add_argument("packageManager", type=str, default="All systems", help="软件包管理器,包括All systems、NPM，PyPI等", required=False, location="json")
        parser.add_argument("pageIndex", type=int, help="分页索引", required=True, location="json")
        parser.add_argument("pageSize", type=int, help="每页返回数据条数", required=True, location="json")

        request_args = parser.parse_args()
        keyword = request_args["keyword"]
        name = request_args["name"]
        packageManager = request_args["packageManager"]
        pageIndex = request_args["pageIndex"]
        pageSize = request_args["pageSize"]

        url = yuantu_url + "/iscas/home/searchNode"
        headers = {
            "Content-Type": "application/json",
            "Usertoken": Yuanu_Usertoken
        }
        body = {
            "keyword": keyword,
            "name": name,
            "packageManager": packageManager,
            "pageIndex": pageIndex,
            "pageSize": pageSize
        }

        try:
            resp = monitor_trans(target_url=url, method='POST', body=body, headers=headers)
            logging.info(f"源图查询软件包第{pageIndex}页的结果是:{resp}")

            if resp["code"] == 200:
                packages = resp["data"]["packages"]

                # 入库
                for package in packages:
                    inputdata = {
                        "_id": package["nodeId"],
                        "name": package["softwareName"],
                        "source": package["packageManager"],
                        "published_time": package["publishedTime"],
                        "version": package["latestVersion"]
                    }
                    mongo_client[mongo_db]["yuantu_collection"].update_one(filter={"_id": package["nodeId"]}, update={'$set': inputdata}, upsert=True)
                return {"code": 200, "message": error_code[200]["message"], "data": {"packages": packages, "pageList": resp["data"]["pageList"]}}, error_code[200]["http"]
            return {"code": resp["code"], "message": error_code[resp["code"]]["message"]}, error_code[resp["code"]]["http"]
        except:
            logging.error(traceback.print_exc())
            return {"code": 400, "message": error_code[400]["message"]}, error_code[400]["http"]


class YuantuSbom(Resource):
    def post(self):
        """
        查询软件包的SBOM信息
        :return:
        """
        logging.info("源图查询软件包的SBOM信息".center(40, "*"))

        # 验证参数
        parser = reqparse.RequestParser()
        parser.add_argument("identity", type=int, help="软件id", required=True, location="json")
        parser.add_argument("source", type=int, default=1, choices=[0, 1], help="数据来源，0为供应链, 1为软件包", required=False, location="json")
        parser.add_argument("part_num", type=int, default=6, choices=[0, 1, 2, 3, 4, 5, 6], help="软件信息类型代号,可选数字0-6，其他数字非法，0为版本信息，1为基本信息，2为组件信息，3为安全性信息，4为依赖性信息，5为合规性信息，6为一次性返回0-5的所有信息", required=False, location="json")
        parser.add_argument("skip", type=int, default=1, help="分页参数", required=False, location="json")
        parser.add_argument("limit", type=int, default=10, help="分页参数", required=False, location="json")

        request_args = parser.parse_args()
        identity = request_args["identity"]
        source = request_args["source"]
        part_num = request_args["part_num"]
        skip = request_args["skip"]
        limit = request_args["limit"]

        url = yuantu_url + "/iscas/sbom/info"
        headers = {
            "Content-Type": "application/json",
            "Usertoken": Yuanu_Usertoken
        }
        body = {
            "identity": identity,
            "source": source,
            "part_num": part_num,
            "skip": skip,
            "limit": limit
        }

        try:
            resp = monitor_trans(target_url=url, method='POST', body=body, headers=headers)
            logging.debug(f"源图查询软件包的SBOM信息结果:{resp}" )

            if resp["code"] == 200:
                # 入库
                result = mongo_client[mongo_db]["yuantu_collection"].find_one({"_id": identity})
                if result:
                    name = result["name"]

                    if part_num in (0, 6):   # 版本信息
                        all_version = resp["data"]["all"] if part_num == 0 else resp["data"]["version_info"].get("all", [])
                        for item in all_version:
                            document = {
                                "_id": item["id"],
                                "name": name,
                                "version": item["version"],
                                "published_time": item["published_time"],
                            }
                            mongo_client[mongo_db]["yuantu_collection"].update_one(filter={"_id": item["id"]}, update={'$set': document}, upsert=True)

                    if part_num in (1, 6):  # 基本信息
                        key_data_pairs = resp["data"]["key_data_pairs"] if part_num == 1 else resp["data"]["base_info"]["key_data_pairs"]
                        document = {
                            "name": key_data_pairs["name"],
                            "author": key_data_pairs["author"],
                            "source": key_data_pairs["source"],
                            "language": key_data_pairs["language"],
                            "size": key_data_pairs["size"],
                            "is_open_source": key_data_pairs["is_open_source"],
                            "published_time": key_data_pairs["published_time"],
                            "url": key_data_pairs["url"],
                            "description": key_data_pairs["description"],
                            "license_name": key_data_pairs["license_name"],
                        }
                        mongo_client[mongo_db]["yuantu_collection"].update_one(filter={"_id": identity}, update={'$set': document}, upsert=True)

                    if part_num in (2, 6):  # 组件信息
                        key_data_pairs = resp["data"].get("key_data_pairs", []) if part_num == 2 else resp["data"]["component_info"].get("key_data_pairs", [])
                        document = {
                            "component_list": key_data_pairs
                        }
                        mongo_client[mongo_db]["yuantu_collection"].update_one(filter={"_id": identity}, update={'$set': document}, upsert=True)

                    if part_num in (3, 6):  # 安全性信息
                        key_data_pairs = resp["data"].get("key_data_pairs", []) if part_num ==3 else resp["data"]["security_info"].get("key_data_pairs", [])
                        document = {
                            "cve_list": key_data_pairs
                        }
                        mongo_client[mongo_db]["yuantu_collection"].update_one(filter={"_id": identity}, update={'$set': document}, upsert=True)

                    if part_num in (4, 6):  # 依赖性信息
                        key_data_pairs = resp["data"].get("key_data_pairs", []) if part_num == 4 else resp["data"]["dependency_info"].get("key_data_pairs", [])
                        document = {
                            "dependency_list": key_data_pairs
                        }
                        mongo_client[mongo_db]["yuantu_collection"].update_one(filter={"_id": identity}, update={'$set': document}, upsert=True)

                    if part_num in (5, 6):  # 合规性信息
                        key_data_pairs = resp["data"].get("key_data_pairs", []) if part_num == 5 else resp["data"]["legality_info"].get("key_data_pairs", [])
                        document = {
                            "legality_list": key_data_pairs
                        }
                        mongo_client[mongo_db]["yuantu_collection"].update_one(filter={"_id": identity}, update={'$set': document}, upsert=True)

                return {"code": 200, "message": error_code[200]["message"], "data": resp["data"]}, error_code[200]["http"]
            return {"code": resp["code"], "message": error_code[resp["code"]]["message"]}, error_code[resp["code"]]["http"]
        except:
            logging.error(traceback.print_exc())
            return {"code": 400, "message": error_code[400]["message"]}, error_code[400]["http"]


class YuantuSbomSpdx(Resource):
    def post(self):
        """
        查询软件包的SBOM+SPDX信息
        :return:
        """
        logging.info("源图查询软件包的SBOM+SPDX信息".center(40, "*"))

        # 验证参数
        parser = reqparse.RequestParser()
        parser.add_argument("identity", type=int, help="软件id", required=True, location="json")
        parser.add_argument("source", type=int, default=1, choices=[0,1], help="数据来源，0为供应链, 1为软件包", required=False, location="json")

        request_args = parser.parse_args()
        identity = request_args["identity"]
        source = request_args["source"]

        url = yuantu_url + "/iscas/sbom/spdx"
        headers = {
            "Content-Type": "application/json",
            "Usertoken": Yuanu_Usertoken
        }
        body = {
            "identity": identity,
            "source": source
        }

        resp = monitor_trans(target_url=url, method='POST', body=body, headers=headers)
        logging.debug(f"源图查询软件包的SBOM+SPDX信息结果:{resp}")

        if resp['code'] == 200:
            data = resp["data"]
            if len(data) == 0:
                mongo_client[mongo_db]["yuantu_collection"].update_one(filter={"nodeId": identity}, update={'$set': {"sbom": data}})
                return {"code": 2, "message": error_code[2]["message"]}, error_code[2]["http"]

            data = resp["data"]
            # 入库
            mongo_client[mongo_db]["yuantu_collection"].update_one(filter={"nodeId": identity}, update={'$set': {"sbom": data}})

            responsedata = data
            responsedata["nodeId"] = identity
            return {"code": 0, "message": error_code[0]["message"], "data": responsedata}, error_code[0]["http"]
        return resp