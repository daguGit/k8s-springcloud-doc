# k8s 学习、安装、使用笔记

## 一、学习

参考网址： https://www.cnblogs.com/kenken2018/p/10332648.html

## 二、安装

### 2.1、centos 安装

```
#参考网址 ：
#优化linux
https://blog.51cto.com/3241766/2398136
#安装
https://blog.51cto.com/3241766/2405624
```



#### 2.1.1 实验成功环境

以下是安装k8s环境成功镜像

| images                                | version       | iamgeid      |
| ------------------------------------- | ------------- | ------------ |
| k8s.gcr.io/kube-proxy                 | v1.14.2       | 5c24210246bb |
| k8s.gcr.io/kube-apiserver             | v1.14.2       | 5eeff402b659 |
| k8s.gcr.io/kube-controller-manager    | v1.14.2       | 8be94bdae139 |
| k8s.gcr.io/kube-scheduler             | v1.14.2       | ee18f350636d |
| quay.io/coreos/flannel                | v0.11.0-amd64 | ff281650a721 |
| k8s.gcr.io/coredns                    | 1.3.1         | eb516548c180 |
| k8s.gcr.io/etcd                       | 3.3.10        | 2c4adeb21b4f |
| k8s.gcr.io/kubernetes-dashboard-amd64 | v1.8.3        | 784cf2722f44 |
| k8s.gcr.io/pause                      | 3.1           | da86e6ba6ca1 |

?

### 2.2、ubutnu安装

参考网址：

 https://blog.csdn.net/weixin_30270889/article/details/102015167

https://blog.csdn.net/heart258/article/details/89914692

### 2.3、kubeasz(大神推荐)

参考网址：

https://github.com/easzlab/kubeasz

## 三、使用

### 3.1 、基本命令

**查看节点状态**

```
kubectl get nodes  -o wide
```

**查看**pod**状态**

```
kubectl get pod --all-namespaces
```

**查看**pod详细信息

```
kubectl descrivbe pod -n <namespace>
```

**强制删除某个pod**

```cpp
# 删除POD
# 参考网址 https://www.jianshu.com/p/470d124845aa
kubectl delete pod PODNAME --force --grace-period=0
```

**强制删除Namespace**

```
kubectl delete namespace NAMESPACENAME --force --grace-period=0
```

**查看副本数**

```
kubectl get deployments
```

**查看集群基本组件状态**

```
kubectl get cs
```

**查看服务**

```
kubectl get services -n kube-system
```

**打标签**

```
#定义标签
kubectl label node host1 disk=ssd
查看标签
kubectl get node --show-labels
```

添加**DNS

```
vim /etc/resolv.conf 添加 nameserver 8.8.8.8
```

**清理**k8s

```
kubeadm reset -f
modprobe -r ipip
lsmod
rm -rf ~/.kube/
rm -rf /etc/kubernetes/
rm -rf /etc/systemd/system/kubelet.service.d
rm -rf /etc/systemd/system/kubelet.service
rm -rf /usr/bin/kube*
rm -rf /etc/cni
rm -rf /opt/cni
rm -rf /var/lib/etcd
rm -rf /var/etcd
```

**清除**kubelet相关

```
sudo apt-get autoremove kubelet
sudo apt-get autoremove kubectl
sudo apt-get autoremove kubeadm
sudo apt-get remove kubelet
sudo apt-get remove kubectl
sudo apt-get remove kubeadm
```

**查看**ip

```
ifconfig
```

**查看磁盘大小**

```
df -h
```

**上传下载**

```
sz
rz
```

**查找文件**

```
sudo find / -name "*name*"
```

### 3.2 、k8s部署容器选择节点

使用给节点打标签的方式，创建容器时选择节点

参考网址：

https://www.cnblogs.com/blazeZzz/p/10297589.html

https://www.cnblogs.com/kenken2018/p/10338846.html

### 3.3 、k8s部署Eureka

 参考网址：https://blog.csdn.net/qq_32641153/article/details/99700281

### 3.4 、k8s部署nacos

#### 3.4.1 部署nacos参考网址

?     https://github.com/nacos-group/nacos-k8s/blob/master/README-CN.md

?     https://developer.aliyun.com/article/738434?spm=a2c6h.12873639.0.0.593a54aaU6yvlC

#### 3.4.2 部署nacos问题

如果挂载nfs失败，查看以下方向：

- 查看挂载

  ```
  #查看挂载命令
    df -hT
  #centos7安装nfs
    参考网址：https://www.cnblogs.com/sxshaolong/p/11010708.html
  ```



- 是否挂载点两个文件夹、以及权限

  ```
  例如:
   nacos挂载点是否有如下文件夹：
      default-datadir-nacos-0-pvc-53fe1f08-5c54-11ea-87a1-0050568ef112
      default-logdir-nacos-0-pvc-53ff1293-5c54-11ea-87a1-0050568ef112
      default-plugindir-nacos-0-pvc-53fd381d-5c54-11ea-87a1-0050568ef112
   容器所在节点是否包含如下文件：
      /var/lib/kubelet/pods/8400cf01-5c64-11ea-87a1-0050568ef112/volumes/kubernetes.io~nfs/pvc-76dfaa5f-5c5a-11ea-87a1-0050568ef112
  ```

- vi /etc/exports 配置

  ```
  /data/nfs-share *(rw,fsid=0,sync,no_root_squash)
  /nfsdir  *(rw,sync,no_root_squash)

  其中
  /data/nfs-share： 为挂载地址
  *：表示任何ip可以访问，
     也可以写成/nfs/prometheus/data/10.10.31.0/24(rw,no_root_squash,no_all_squash,sync)，其中
     10.10.31.0/24：这个是运行访问NFS的IP范围，也就是10.10.31开头的IP，24是掩码长度。
  (rw,no_root_squash,no_all_squash,sync)：
  rw：可读写的权限；
  ro：只读的权限；
  no_root_squash：登入到NFS主机的用户如果是root，该用户即拥有root权限；
  root_squash：登入NFS主机的用户如果是root，该用户权限将被限定为匿名使用者nobody；
  all_squash：不管登陆NFS主机的用户是何权限都会被重新设定为匿名使用者nobody。
  anonuid：将登入NFS主机的用户都设定成指定的user id，此ID必须存在于/etc/passwd中。
  anongid：同anonuid，但是变成group ID就是了！
  sync：资料同步写入存储器中。
  async：资料会先暂时存放在内存中，不会直接写入硬盘。
  insecure：允许从这台机器过来的非授权访问。
  ```



- 重启服务：

  参考网址 https://www.cnblogs.com/sxshaolong/p/11010708.html

  ```
  systemctl restart rpcbind
  systemctl restart nfs
  ```

### **3.5 、k8s部署dashboard**

```
#下载yml
http://mirror.faasx.com/kubernetes/dashboard/master/src/deploy/recommended/kubernetes-dashboard.yaml
#修改yml
https://blog.csdn.net/jholy/article/details/85125997
#参考
https://www.jianshu.com/p/858df8cc6b95
```



## 四、问题

### **4.1、从节点，不能访问server**

将 主节点的/etc/kubernetes/admin.conf 拷贝到从节点上，主要来复制admin.conf
执行  ：

```
echo "export KUBECONFIG=/etc/kubernetes/admin.conf" >> ~/.bash_profile
source ~/.bash_profile
```

### **4.2 主节点coredns back-off**

A、尝试修改 vim /etc/resolv.conf
	然后重启服务

```
systemctl daemon-reload systemctl restart docker
```

B、防火墙（iptables）规则错乱或者缓存导致的，可以依次执行以下命令进行解决：

```
systemctl stop kubelet
systemctl stop docker
iptables --flush
iptables -tnat --flush
systemctl start kubelet
systemctl start docker
```

C、或者删除pod

### **4.3、token令牌失效，解决方法：**

1、在master节点执行下面的命令

```
 sudo kubeadm token create
```

2、然后再执行下面的命令重新生成注册令牌

```
sudo kubeadm token create --print-join-command
```

### **4.4、若有镜像下载不下来，可以遵循以下步骤**

1、查询镜像：docker search <镜像>
2、拉取镜像：docker pull <镜像>
3、tag镜像：docker tag <镜像> <镜像>

```
#执行以下命令，拉取k8simage
vi ./images.sh
#在images.sh 中添加如下内容----start--------
#!/bin/bash
url=registry.cn-hangzhou.aliyuncs.com/google_containers
version=v1.14.2
images=(`kubeadm config images list --kubernetes-version=$version|awk -F '/' '{print $2}'`)
for imagename in ${images[@]} ; do
  docker pull $url/$imagename
  docker tag $url/$imagename k8s.gcr.io/$imagename
  docker rmi -f $url/$imagename
done
#在images.sh 中添加如下内容--------end-----
chmod 777 ./image.sh
./image.sh

```




### **4.5、pod所在的节点挂了，pod任然在running状态，并没有转移到起到节点**

https://kubernetes.io/docs/concepts/nodes/node/

### **4.6、ubuntu完全卸载docker**

https://www.cnblogs.com/shmily3929/p/12085163.html

### **4.7、安装特定版本docker**

https://www.runoob.com/docker/ubuntu-docker-install.html

```
#先通过以下命令版本信息
apt-cache madison docker-ce
#安装指定版本docker
sudo apt-get install docker-ce=5:18.09.7~3-0~ubuntu-xenial docker-ce-cli=5:18.09.7~3-0~ubuntu-xenial containerd.io
```

### **4.8、安装指定版本k8s**

```
sudo apt install -y kubelet=1.14.2-00 kubeadm=1.14.2-00 kubectl=1.14.2-00
```

### **4.9、**cni网址与podIp不在一个段

发现cni0的这个网卡地址是10.244.1.1，明显与报错中的10.244.2.1不一致，将其改为10.244.2.1，重启网络服务，回到master，发现容器正常运行

可使用nmtui，然后将cni的地址改掉

```
systemctl restart network
```

也可将10.244.1.1的那个网卡删掉，它会自己重建的

也可将10.244.1.1的那个网卡删掉，它会自己重建的

### **4.10、在节点中不能ping通容器ip**

参考网址：https://www.cnblogs.com/cxbhakim/p/9626507.html
1：ping 节点
2：查看 flanet 网卡、查看dns 查看proxy
3：这是由于linux还有底层的iptables，所以在node上分别执行：

```
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -F
iptables -L -n
```

### **4.11 初始化指定版本k8s**

```
kubeadm init --apiserver-advertise-address 192.168.2.178 --pod-network-cidr=10.244.0.0/16 --kubernetes-version=v1.14.2
```

4.12 、ping不同百度

```
#1、编辑Linux中的网络配置文件
	vi /etc/sysconfig/network-scripts/ifcfg-ens33
#注 网络配置文件名可能会有不同，在输入到ifcfg时，可以连续按两下tab键，获取提示，比如我的机器 为 ifcfg-ens33

#内容替换如下：
    TYPE=”Ethernet”
    BOOTPROTO=”static”
    NAME=”ens33”
    UUID=”1f093d71-07de-4ca5-a424-98e13b4e9532”
    DEVICE=”ens33”
    ONBOOT=”yes” #网络设备开机启动
    IPADDR=”192.168.126.110”
    NETMASK=”255.255.255.0” #子网掩码
    GATEWAY=”192.168.126.1” #网关IP
    DNS1= 8.8.8.8
    DNS2=8.8.8.4

#3、重启网络服务
　　service network restart

#4、DNS文件配置
    vi /etc/resolv.conf
    nameserver 8.8.8.8
    nameserver 8.8.4.4
```

### 4.12、kubelet cgroup driver: "cgroupfs" is different from docker cgroup driver: "systemd

?    	https://www.cnblogs.com/hongdada/p/9771857.html