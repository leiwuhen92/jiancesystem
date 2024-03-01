# 外部系统调用
    调用外部系统以分析固件


# 部署
## 1、部署mongo
### 结构：
    mongo/
    ├── configdb
    │   └── mongod.conf
    └── db
配置mongod.conf：
```
storage:
    dbPath: /data/db
    engine: wiredTiger
security:
    authorization: enabled  # 开启登录认证
net:
    port: 27017
    bindIp: 192.168.11.45  # 修改成规划的mongo服务器地址
```

### docker 运行mongo：
    docker run --name mongodb -d \
      -p 27017:27017 \
      -v /home/mongo/db:/data/db \
      -v /home/mongo/configdb:/data/configdb \
      -v /etc/localtime:/etc/localtime \
      -e MONGO_INITDB_ROOT_USERNAME=admin \
      -e MONGO_INITDB_ROOT_PASSWORD=Admin_123 \
      mongo -f /data/configdb/mongod.conf

### 进入mongo容器
    docker exec -it mongo mongosh --host 127.0.0.1 --port 27017 -u "admin" -p "Admin_123" --authenticationDatabase "admin"
    
## 2、gunicorn启动
    gunicorn -c gunicorn_config.py api:flask_app

## 3、容器启动
### 镜像制作
     docker build -t externsystem:1.0 .
### 容器使用
    # 更换config.py中的配置项
    docker run -d --name external -p 5001:5000 \
        -v /nas/external/config.py:/home/restfulapi/config.py \
        -v /nas/external/spider_config.py:/home/restfulapi/spider_config.py \
        -v /nas/external/firmwares:/home/restfulapi/firmwares \
        --init externsystem:1.0

## 4、API访问：http://host:5001/xxx