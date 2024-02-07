# 作者：zhangqiang
# 时间：2023-12-27
# 描述：gunicorn配置文件
# 使用：gunicorn -c gunicorn_config.py api:flask_app

from gevent import monkey
monkey.patch_all()
import multiprocessing


bind = "0.0.0.0:5000"     # 绑定ip和端口号
timeout = 60              # 超时
worker_class = "gevent"   # 工作进程类：使用gevent模式，还可以使用sync 模式，默认的是sync模式
workers = multiprocessing.cpu_count() * 2 + 1    # 工作进程数

# chdir = '/home/server'  # gunicorn要切换到的目的工作目录
pidfile = "/tmp/gunicorn.pid"
loglevel = "info"  # 日志级别
accesslog = "/var/log/gunicorn_access.log"   # 访问日志文件
errorlog = "/var/log/gunicorn_error.log"     # 错误日志文件
access_log_format = '%(t)s %(p)s %(h)s "%(r)s" %(s)s %(L)s %(b)s %(f)s" "%(a)s"'  #设置gunicorn访问日志格式，错误日志无法设置

