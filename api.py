# 作者：zhangqiang
# 时间：2023-12-5
# 描述：restful_api接口
# 启动命令：gunicorn -c gunicorn_config.py restfulapi.api:flask_app

from flask import Flask, request, g
from flask_restful import Api
from views.podding import PoddingAnalysis, PoddingSearchOption, PoddingSearch, PoddingFirmDetail, PoddingSimilar, PoddingVulGraph
from views.yuanxi import YuanxiDetect, YuanxiDetectResult, YuanxiCodeLintShow, YuanxiDownload
from views.yuantu import YuantuSearchNode, YuantuSbom, YuantuSbomSpdx
from views.ces import GetLinks, UpdateLinks,  GetCondition, SpiderDisplay
from utils.update_token import get_token, check_token, create_token, write_2_py
from utils.common import logging
from config import yuanxi_user, yuanxi_pwd
from error_code import error_code

# flask对象
flask_app = Flask(__name__)
flask_api = Api(flask_app)


# 调用podding
flask_api.add_resource(PoddingAnalysis, "/api/podding/analysis")
flask_api.add_resource(PoddingSearchOption, "/api/podding/SearchOption")
flask_api.add_resource(PoddingSearch, "/api/podding/Search")
flask_api.add_resource(PoddingFirmDetail, "/api/podding/firmdetail")
flask_api.add_resource(PoddingSimilar, "/api/podding/similar")
flask_api.add_resource(PoddingVulGraph, "/api/podding/vuln_graph")

# 调用源析
flask_api.add_resource(YuanxiDetect, "/api/yuanxi/detect")
flask_api.add_resource(YuanxiDetectResult, "/api/yuanxi/getDetectResult")
flask_api.add_resource(YuanxiCodeLintShow, "/api/yuanxi/codeLintShow")
flask_api.add_resource(YuanxiDownload, "/api/yuanxi/download")

# 调用源图
flask_api.add_resource(YuantuSearchNode, "/api/yuantu/searchNode")
flask_api.add_resource(YuantuSbom, "/api/yuantu/sbom")
flask_api.add_resource(YuantuSbomSpdx, "/api/yuantu/sbomspdx")

# 爬虫固件
flask_api.add_resource(GetLinks, "/api/spider/getlinks"),
flask_api.add_resource(UpdateLinks, "/api/spider/updatelinks"),

flask_api.add_resource(GetCondition, "/api/spider/getcondition"),
flask_api.add_resource(SpiderDisplay, "/api/spider/display")


@flask_app.before_request
def verify_yuanxi_token():
    # 非源析接口不处理
    if "yuanxi" not in request.path:
        return None

    try:
        token = get_token()
        is_valid = check_token(token)
        logging.info("yaunxi'token is valid:%s" % is_valid)
        if is_valid:
            return None
        else:
            token = create_token(yuanxi_user, yuanxi_pwd)
            write_2_py(token)
    except:
        return {"code": 400, "message": error_code[400]["message"]}, error_code[400]["http"]

    return None


if __name__ == '__main__':
    flask_app.run(host='0.0.0.0')





