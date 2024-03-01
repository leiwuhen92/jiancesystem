# 作者：zhangqiang
# 时间：2023-12-5
# 描述：错误码

error_code = {
    200: {"http": 200, "message": "成功", "log": "ok"},
    400: {"http": 400, "message": "发送请求失败", "log": "send request failed"},

    103: {"http": 400, "message": "输入名称版本已存在对应的检测算法", "log": "输入名称版本已存在对应的检测算法"},
    40001: {"http": 401, "message": "登陆失败", "log": "login failed"},
    30004: {"http": 401, "message": "token超时或认证失败或没有token", "log": "token超时或认证失败或没有token"},
    30003: {"http": 400, "message": "查不到该用户", "log": "unable to find the user"},
    114: {"http": 400, "message": "未找到相关检测", "log": "no corresponding record found"},
    40002: {"http": 400, "message": "参数不合法", "log": "illegal parameters"},
    42083: {"http": 400, "message": "缺少参数", "log": "missing parameter"},
    102: {"http": 400, "message": "请求参数校验错误", "log": "请求参数校验错误"},

    500: {"http": 400, "message": "uploadId不存在，", "log": "uploadId not exist, "},
    404: {"http": 400, "message": "文件不存在，", "log": "file not exist, "},

    38: {"http": 400, "message": "错误的请求", "log": "request data error"},
    39: {"http":400, "message": "文件大小不允许小于0或大于2147483647", "log": "totalSize less than 1 or more than 2147483647"},
    56: {"http":400, "message": "文件名格式错误", "log": "file name format error"},
    104: {"http":400, "message": "固件md5格式错误", "log": "firmware md5 format error"}
}
