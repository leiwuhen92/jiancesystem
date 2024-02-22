FROM ubuntu:20.04
MAINTAINER zq

ENV TZ=Asia/Shanghai
ENV DEBIAN_FRONTEND=noninteractive
# Turns off buffering for easier container logging
ENV PYTHONUNBUFFERED=1

COPY . /home/restfulapi/
WORKDIR /home/restfulapi/

RUN echo "nameserver 114.114.114.114" >> /etc/resolv.conf
RUN echo "nameserver 8.8.8.8" >> /etc/resolv.conf
RUN sed -i 's/\:\/\/archive\.ubuntu\.com/\:\/\/mirrors\.tuna\.tsinghua\.edu\.cn/g' /etc/apt/sources.list

RUN apt-get -y update \
    && apt-get -y dist-upgrade \
    && apt-get -y install python3-pip locales vim unzip \
	&& locale-gen zh_CN.UTF-8 \
    && pip3 install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt \
    # clean
    && apt -y autoremove \
    && rm -rf /var/cache/apk/* \
    && rm -rf /var/lib/apt/lists/*
# 解决容器内中文乱码
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8
ENV LANGUAGE C.UTF-8

# Creates a non-root user and adds permission to access the /home/restfulapi/ folder
RUN adduser --disabled-password --gecos "" nist && chown -R nist /home/restfulapi && chown -R nist /var/log
USER nist

ENTRYPOINT ["/usr/local/bin/gunicorn", "-c", "gunicorn_config.py",  "api:flask_app"]