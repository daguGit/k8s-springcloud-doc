# k8s-springcloud-doc
## 写作目的与思路
此文档是整理k8s-springcloud学习过程，方便其他人参考。详见参考wiki。
首先之前一直在使用springboot  
之后听说了springcloud，学习程序员dd的cloud教程  
之后接触到了zhoutaoo/springcloud脚手架，开始深入学习此工程包括oauth、mq、消息流转  
之后学习使用docker、docker-compose单独部署zhoutaoo/springcloud脚手架  
之后学习使用k8s搭建集群，将k8s-springcloud工程弄成docker镜像部署   
之后在ext-js工程中添加动态路由页面，增加gateway-admin中心，仓库中暂未添加  
之后测试将springboot-admin注册到nacos，测试admin的功能：common-admin模块   
之后测试mq的生产与消费并接入zipkin：service-provider与service-consumer模块  
简单测试es使用，见3.4  
测试redis的相关功能，解决缓存常见问题与缓存击穿  




## 快速开始

# 微服务学习笔记

## 一、了解微服务
本小节具体可参考 
[程序员dd](http://blog.didispace.com/ "程序员DD")、
[方志朋专栏](https://www.fangzhipeng.com/ "方志朋专栏")、
[springcloud中文索引](http://springcloud.fun/ "springcloud中文")
系列博客
### 1.1、微服务概念

### 1.2 、微服务中心组件

## 二、微服务组件使用

### 2.1 、原生组件

- Eureka
- Feign
- hystrix
- zuul/gateway

### 2.2 、其他组件（alibaba）

- Nacos
- RocketMQ

### 2.3、其他

- rabbitMq
    - [参考本页wiki](http://192.168.168.163/guyingzhi/k8s-springcloud-doc/wikis/k8s-springcloud(3)-rabbitmq%E5%AD%A6%E4%B9%A0 "rabbitMq学习使用")
### 2.4、拓展
- zookeeper与eureka对比区别
    - 百度搜索"zk与eureka"即可，例如 [https://blog.csdn.net/gaowenhui2008/article/details/70237908](https://blog.csdn.net/gaowenhui2008/article/details/70237908)
- kafka与mq区别、kafka使用
    - kafka使用 [参考本页wiki](http://192.168.168.163/guyingzhi/k8s-springcloud-doc/wikis/k8s-springcloud(5)-kafka%E5%AD%A6%E4%B9%A0 "docker学习使用")
    - 与mq区别 [参考他人博客](https://blog.csdn.net/yunfeng482/article/details/72856762)


## 三、微服务部署使用

### 3.1 、Docker学习使用

- [参考本页wiki](http://192.168.168.163/guyingzhi/k8s-springcloud-doc/wikis/k8s-springcloud(1)-docker%E5%AD%A6%E4%B9%A0 "docker学习使用")

 

### 3.2 、k8s学习使用
- [参考本页wiki](http://192.168.168.163/guyingzhi/k8s-springcloud-doc/wikis/k8s-springcloud(2)-k8s%E5%AD%A6%E4%B9%A0 "k8s学习使用")

### 3.3 、nginx使用
- [参考本页wiki](http://192.168.168.163/guyingzhi/k8s-springcloud-doc/wikis/k8s-springcloud(4)-nginx%E5%AD%A6%E4%B9%A0 "nginx学习使用")

### 3.4 、关于日志收集elk组件使用
- [ELK搭建参考网址](https://jicki.me/docker/kubernetes/2019/07/02/kuebrnetes-NEW-ELK/)

但是在使用的时候，出现 es不能使用root账户创建、kibana不能连接到es等问题，暂未完全解决。

- 建议先参考 es学习教程
    - 浏览器安装es查看插件 https://chrome.google.com/webstore/detail/elasticsearch-head/ffmkiejjmecolpfloofpjologoblkegm
    - 随便一篇es简单使用教程 例如[全文搜索引擎 Elasticsearch 入门教程](http://www.ruanyifeng.com/blog/2017/08/elasticsearch.html)

### 3.5 、 关于CI\CD等问题（待）
 - [解读Gitlab-ci.yml文件](https://segmentfault.com/a/1190000019540360)  	    
 - [解读Deployment.yml 文件1](http://www.imooc.com/article/280085)
 - [解读Deployment.yml 文件2](https://www.cnblogs.com/twobrother/p/11082918.html)
        
### 3.6 、redis的部署与使用

## 四、微服务脚手架学习
- [参考 zhoutao github](https://github.com/zhoutaoo/SpringCloud)
- [参考 lengleng/pig](https://gitee.com/log4j/pig)


### 4.1、部署

### 4.2、解析
 - authorizaiton模块 
    - [关于author认证问题参考](https://blog.csdn.net/ThinkWon/article/details/103761687)
    - [关于author认证问题参考2](https://segmentfault.com/a/1190000021081318)
    - [关于author认证问题参考3](https://juejin.im/post/5e71c727518825490b649f46)
## 五、关于本仓库下k8s-springcloud工程
- [参考本页wiki](http://192.168.168.163/guyingzhi/k8s-springcloud-doc/wikis/k8s-springcloud(99)-k8s_springcloud%E5%AD%A6%E4%B9%A0 "k8s_springcloud学习使用")








