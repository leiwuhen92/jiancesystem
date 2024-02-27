# 外部系统调用
    调用外部系统以分析固件


# 部署
## 1、部署mongo
    docker run --name mongodb -d \
      -p 27017:27017 \
      -v /home/mongo/db:/data/db \
      -v /home/mongo/configdb:/data/configdb \
      -v /etc/localtime:/etc/localtime \
      -e MONGO_INITDB_ROOT_USERNAME=admin \
      -e MONGO_INITDB_ROOT_PASSWORD=Admin_123 \
      mongo -f /data/configdb/mongod.conf
    
    docker exec -it mongo mongosh --host 127.0.0.1 --port 27017 -u "admin" -p "Admin_123" --authenticationDatabase "admin"
    
## 2、gunicorn启动
    gunicorn -c gunicorn_config.py api:flask_app

## 3、容器启动
### 镜像制作
     docker build -t externsystem:1.0 .
### 容器使用
    # 更换config.py中的配置项
    docker run -d --name external -p 5000:5000 -v /home/external/config.py:/home/restfuapi/config.py -v /home/external/firmwares:/home/restfulapi/firmwares --init externsystem:1.0  
    docker run -d --name external -p 5000:5000 -v /home/external/:/home/restfulapi/ --init externsystem:1.0