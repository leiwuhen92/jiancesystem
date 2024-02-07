# 作者：zhangqiang
# 时间：2023-12-5
# 描述：restful_api接口
# 启动命令：gunicorn -c gunicorn_config.py restfulapi.api:flask_app

from flask import Flask, request, g
from flask_restful import Api
from views.podding import PoddingAnalysis, PoddingSearchOption, PoddingSearch, PoddingFirmDetail, PoddingSimilar, PoddingVulGraph
from views.yuanxi import YuanxiDetect, YuanxiDetectResult, YuanxiCodeLintShow, YuanxiDownload
from views.yuantu import YuantuSearchNode, YuantuSbom, YuantuSbomSpdx


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


if __name__ == '__main__':
    flask_app.run()





