# 外部系统调用
    调用外部系统以分析固件


# 使用方式
## gunicorn启动
    gunicorn -c gunicorn_config.py api:flask_app

## 容器启动
### 镜像制作
     docker build -t externsystem:1.0 .
### 容器使用
    docker run -d --name external -p 5000:5000 -v /home/restfulapi/config.py:/home/restfuapi/config.py -v /home/restfulapi/firmwares:/home/restfulapi/firmwares --init externsystem:1.0  # 更换config.py中的配置项
    docker run -d --name external -p 5000:5000 -v /home/restfulapi/:/home/restfulapi/ --init externsystem:1.0