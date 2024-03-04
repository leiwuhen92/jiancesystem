# Crawler engine system

# 作者：zhangqiang
# 时间：2024-02-29
# 描述：调用爬虫引擎系统
import json
import re
import traceback
from flask_restful import Resource, reqparse
import requests
requests.packages.urllib3.disable_warnings()
from config import mongo_db
from common import mongo_client, logging, get_length_string
from error_code import error_code


def add_escape(input):
    """
    添加转义符
    :param input:
    :return:
    """
    reserved_chars = r"?&|!{}[]()^~:+- ."
    replace = ["\\" + l for l in reserved_chars]
    trans = input.maketrans(dict(zip(reserved_chars, replace)))
    return input.translate(trans)


class GetCondition(Resource):
    def get(self):
        logging.info("in get spider firmware display condition".center(40, "*"))
        vendor_list = mongo_client[mongo_db]["spider"].distinct("vendor")
        device_type_list = mongo_client[mongo_db]["spider"].distinct("type")

        # 库中厂商、设备类型可能为空字符
        if '' in vendor_list:
            vendor_list.remove('')
        if '' in device_type_list:
            device_type_list.remove('')

        response_data = {"vendor": vendor_list, "device_type": device_type_list}
        return {"code": 200, "message": error_code[200]["message"], "data": response_data}, error_code[200]["http"]


class SpiderDisplay(Resource):
    def post(self):
        logging.info("in spider firmware display".center(40, "*"))

        parser = reqparse.RequestParser()
        parser.add_argument("page_num", type=int, help="当前页数", required=True, location="json")
        parser.add_argument("page_size", type=int, default=10, help="每页条数", required=False, location="json")
        parser.add_argument("md5", type=str, help="固件md5", required=False, trim=True, location="json")
        parser.add_argument("name", type=str, help="固件名称", required=False, trim=True, location="json")
        parser.add_argument("vendor", type=str, action='append', help="固件的厂商列表", required=False, trim=True, location="json")
        parser.add_argument("start_size", type=int, help="开始大小", required=False, location="json")
        parser.add_argument("end_size", type=int, help="结束大小", required=False, location="json")
        parser.add_argument("device_type", type=str, action='append', help="设备类型列表", required=False, trim=True, location="json")
        parser.add_argument("is_download", type=int, choices=[-1, 0, 1, 2], help="固件下载状态, -1为全部, 0为未下载, 1为已下载, 2下载失败", required=False, location="json")

        request_args = parser.parse_args()
        page_num = request_args["page_num"]
        page_size = request_args["page_size"]
        firmware_md5 = request_args["md5"]
        firmware_name = request_args["name"]
        vendor_list = request_args["vendor"]
        start_size = request_args["start_size"]
        end_size = request_args["end_size"]
        device_type_list = request_args["device_type"]
        is_download = request_args["is_download"]

        # 请求数据过小
        if page_num < 1 or page_size < 1 or page_num > 2147483647:
            logging.error(error_code[38]["log"])
            return {"code": 38, "message": error_code[38]["message"]}, error_code[38]["http"]

        match = {}
        # 固件md5
        if firmware_md5 is not None:
            if re.match(r'^[a-z0-9]{1,32}$', firmware_md5) is None:
                logging.error(error_code[104]["log"])
                return {"code": 104, "message": error_code[104]["message"]}, error_code[104]["http"]
            match["md5"] = {'$regex': f".*{firmware_md5}.*"}
        # 固件名(不包含特殊字符，长度在1-200之间)
        if firmware_name is not None:
            if re.match(r'^[^\\\'\"$=`;*/]{1,200}$', firmware_name) is None:
                logging.error(error_code[56]["log"])
                return {"code": 56, "message": error_code[56]["message"]}, error_code[56]["http"]
            match["name"] = {'$regex': f".*{add_escape(firmware_name)}.*"}
        # 厂商
        if vendor_list is not None:
            match["vendor"] = {'$in': vendor_list}
        # 固件大小
        if start_size is not None:
            if start_size < 1 or start_size > 2147483647:
                logging.error(error_code[39]["log"])
                return {"code": 39, "message": error_code[39]["message"]}, error_code[39]["http"]
            match["size"] = {'$gte': start_size}
        if end_size is not None:
            if end_size < 1 or end_size > 2147483647:
                logging.error(error_code[39]["log"])
                return {"code": 39, "message": error_code[39]["message"]}, error_code[39]["http"]
            if start_size is not None and start_size > end_size:
                logging.error(error_code[38]["log"])
                return {"code": 38, "message": error_code[38]["message"]}, error_code[38]["http"]
            if "size" in match:
                match["size"]['$lte'] = end_size
            else:
                match["size"] = {'$lte': end_size}
        # 设备类型
        if device_type_list is not None:
            match["type"] = {'$in': device_type_list}
        # 下载状态
        if is_download is not None:
            if is_download == -1:
                pass
            else:
                match['is_download'] = is_download
        logging.info(match)
        try:
            skip = (page_num - 1) * page_size
            spider_aggregate = mongo_client[mongo_db]["spider"].aggregate([{"$facet": {
                "total": [
                    {'$match': match},
                    {'$count': "total_count"}
                ],
                "firmware_list": [
                    {'$match': match},
                    {'$sort': {"start_time": -1, "_id": -1}},
                    {'$skip': skip},
                    {'$limit': page_size}
                ]
            }}])

            download_map = { 0: "未下载", 1: "已下载", 2: "下载失败"}
            total = 0
            firmware_list = []
            for item in spider_aggregate:
                for i in item["total"]:
                    total = i["total_count"]
                for j in item["firmware_list"]:
                    firmware_list.append({
                        'name': j['name'],
                        'md5': j['md5'],
                        'version': j['version'],
                        'vendor': j['vendor'],
                        'size': get_length_string(j['size']) if j['size'] else None,
                        'device_type': j['type'],
                        'web_url': j['web_url'],
                        'download_url': j['download_url'],
                        'is_download': download_map[j['is_download']]
                        # 'location': j['location'],
                        # 'create_time': j['create_time'],
                        # 'update_time': j['update_time']
                    })
            response_data = {"total": total, "page_num": page_num, "firmware": firmware_list}
            return {"code": 200, "message": error_code[200]["message"], "data": response_data}, error_code[200]["http"]
        except:
            logging.error(traceback.print_exc())
            return {"code": 400, "message": error_code[400]["message"]}, error_code[400]["http"]


class GetLinks(Resource):
    def get(self):
        logging.info("in get website sources for crawler engine systems ".center(40, "*"))

        with open('spider_config.py', 'r') as file:
            url_dict = json.load(file)

        url_list = []
        for k, v in url_dict.items():
            url_list.append({"url": k, "flag": v})

        response_data = {'links': url_list}
        return {"code": 200, "message": error_code[200]["message"], "data": response_data}, error_code[200]["http"]


class UpdateLinks(Resource):
    def post(self):
        logging.info("in configure website sources for crawler engine systems ".center(40, "*"))

        parser = reqparse.RequestParser()
        parser.add_argument("links", type=str, action='append', help="网站源列表", required=True, trim=True, location="json")

        request_args = parser.parse_args()
        links = request_args["links"]

        with open('spider_config.py', 'r') as file:
            url_list = json.load(file)

        # 更新网站源
        for k in links:
            url_list[k] = 1
        with open("spider_config.py", 'w') as fd:
            json.dump(url_list, fd, indent=4, ensure_ascii=False)

        logging.info("update config links ok.")
        return {"code": 200, "message": error_code[200]["message"]}, error_code[200]["http"]








