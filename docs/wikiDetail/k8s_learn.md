# k8s ѧϰ����װ��ʹ�ñʼ�

## һ��ѧϰ

�ο���ַ�� https://www.cnblogs.com/kenken2018/p/10332648.html

## ������װ

### 2.1��centos ��װ

```
#�ο���ַ ��
#�Ż�linux
https://blog.51cto.com/3241766/2398136
#��װ
https://blog.51cto.com/3241766/2405624
```



#### 2.1.1 ʵ��ɹ�����

�����ǰ�װk8s�����ɹ�����

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

### 2.2��ubutnu��װ

�ο���ַ��

 https://blog.csdn.net/weixin_30270889/article/details/102015167

https://blog.csdn.net/heart258/article/details/89914692

### 2.3��kubeasz(�����Ƽ�)

�ο���ַ��

https://github.com/easzlab/kubeasz

## ����ʹ��

### 3.1 ����������

**�鿴�ڵ�״̬**

```
kubectl get nodes  -o wide
```

**�鿴**pod**״̬**

```
kubectl get pod --all-namespaces
```

**�鿴**pod��ϸ��Ϣ

```
kubectl descrivbe pod -n <namespace>
```

**ǿ��ɾ��ĳ��pod**

```cpp
# ɾ��POD
# �ο���ַ https://www.jianshu.com/p/470d124845aa
kubectl delete pod PODNAME --force --grace-period=0
```

**ǿ��ɾ��Namespace**

```
kubectl delete namespace NAMESPACENAME --force --grace-period=0
```

**�鿴������**

```
kubectl get deployments
```

**�鿴��Ⱥ�������״̬**

```
kubectl get cs
```

**�鿴����**

```
kubectl get services -n kube-system
```

**���ǩ**

```
#�����ǩ
kubectl label node host1 disk=ssd
�鿴��ǩ
kubectl get node --show-labels
```

���**DNS

```
vim /etc/resolv.conf ��� nameserver 8.8.8.8
```

**����**k8s

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

**���**kubelet���

```
sudo apt-get autoremove kubelet
sudo apt-get autoremove kubectl
sudo apt-get autoremove kubeadm
sudo apt-get remove kubelet
sudo apt-get remove kubectl
sudo apt-get remove kubeadm
```

**�鿴**ip

```
ifconfig
```

**�鿴���̴�С**

```
df -h
```

**�ϴ�����**

```
sz
rz
```

**�����ļ�**

```
sudo find / -name "*name*"
```

### 3.2 ��k8s��������ѡ��ڵ�

ʹ�ø��ڵ���ǩ�ķ�ʽ����������ʱѡ��ڵ�

�ο���ַ��

https://www.cnblogs.com/blazeZzz/p/10297589.html

https://www.cnblogs.com/kenken2018/p/10338846.html

### 3.3 ��k8s����Eureka

 �ο���ַ��https://blog.csdn.net/qq_32641153/article/details/99700281

### 3.4 ��k8s����nacos

#### 3.4.1 ����nacos�ο���ַ

?     https://github.com/nacos-group/nacos-k8s/blob/master/README-CN.md

?     https://developer.aliyun.com/article/738434?spm=a2c6h.12873639.0.0.593a54aaU6yvlC

#### 3.4.2 ����nacos����

�������nfsʧ�ܣ��鿴���·���

- �鿴����

  ```
  #�鿴��������
    df -hT
  #centos7��װnfs
    �ο���ַ��https://www.cnblogs.com/sxshaolong/p/11010708.html
  ```



- �Ƿ���ص������ļ��С��Լ�Ȩ��

  ```
  ����:
   nacos���ص��Ƿ��������ļ��У�
      default-datadir-nacos-0-pvc-53fe1f08-5c54-11ea-87a1-0050568ef112
      default-logdir-nacos-0-pvc-53ff1293-5c54-11ea-87a1-0050568ef112
      default-plugindir-nacos-0-pvc-53fd381d-5c54-11ea-87a1-0050568ef112
   �������ڽڵ��Ƿ���������ļ���
      /var/lib/kubelet/pods/8400cf01-5c64-11ea-87a1-0050568ef112/volumes/kubernetes.io~nfs/pvc-76dfaa5f-5c5a-11ea-87a1-0050568ef112
  ```

- vi /etc/exports ����

  ```
  /data/nfs-share *(rw,fsid=0,sync,no_root_squash)
  /nfsdir  *(rw,sync,no_root_squash)

  ����
  /data/nfs-share�� Ϊ���ص�ַ
  *����ʾ�κ�ip���Է��ʣ�
     Ҳ����д��/nfs/prometheus/data/10.10.31.0/24(rw,no_root_squash,no_all_squash,sync)������
     10.10.31.0/24����������з���NFS��IP��Χ��Ҳ����10.10.31��ͷ��IP��24�����볤�ȡ�
  (rw,no_root_squash,no_all_squash,sync)��
  rw���ɶ�д��Ȩ�ޣ�
  ro��ֻ����Ȩ�ޣ�
  no_root_squash�����뵽NFS�������û������root�����û���ӵ��rootȨ�ޣ�
  root_squash������NFS�������û������root�����û�Ȩ�޽����޶�Ϊ����ʹ����nobody��
  all_squash�����ܵ�½NFS�������û��Ǻ�Ȩ�޶��ᱻ�����趨Ϊ����ʹ����nobody��
  anonuid��������NFS�������û����趨��ָ����user id����ID���������/etc/passwd�С�
  anongid��ͬanonuid�����Ǳ��group ID�����ˣ�
  sync������ͬ��д��洢���С�
  async�����ϻ�����ʱ������ڴ��У�����ֱ��д��Ӳ�̡�
  insecure���������̨���������ķ���Ȩ���ʡ�
  ```



- ��������

  �ο���ַ https://www.cnblogs.com/sxshaolong/p/11010708.html

  ```
  systemctl restart rpcbind
  systemctl restart nfs
  ```

### **3.5 ��k8s����dashboard**

```
#����yml
http://mirror.faasx.com/kubernetes/dashboard/master/src/deploy/recommended/kubernetes-dashboard.yaml
#�޸�yml
https://blog.csdn.net/jholy/article/details/85125997
#�ο�
https://www.jianshu.com/p/858df8cc6b95
```



## �ġ�����

### **4.1���ӽڵ㣬���ܷ���server**

�� ���ڵ��/etc/kubernetes/admin.conf �������ӽڵ��ϣ���Ҫ������admin.conf
ִ��  ��

```
echo "export KUBECONFIG=/etc/kubernetes/admin.conf" >> ~/.bash_profile
source ~/.bash_profile
```

### **4.2 ���ڵ�coredns back-off**

A�������޸� vim /etc/resolv.conf
	Ȼ����������

```
systemctl daemon-reload systemctl restart docker
```

B������ǽ��iptables��������һ��߻��浼�µģ���������ִ������������н����

```
systemctl stop kubelet
systemctl stop docker
iptables --flush
iptables -tnat --flush
systemctl start kubelet
systemctl start docker
```

C������ɾ��pod

### **4.3��token����ʧЧ�����������**

1����master�ڵ�ִ�����������

```
 sudo kubeadm token create
```

2��Ȼ����ִ�������������������ע������

```
sudo kubeadm token create --print-join-command
```

### **4.4�����о������ز�������������ѭ���²���**

1����ѯ����docker search <����>
2����ȡ����docker pull <����>
3��tag����docker tag <����> <����>

```
#ִ�����������ȡk8simage
vi ./images.sh
#��images.sh �������������----start--------
#!/bin/bash
url=registry.cn-hangzhou.aliyuncs.com/google_containers
version=v1.14.2
images=(`kubeadm config images list --kubernetes-version=$version|awk -F '/' '{print $2}'`)
for imagename in ${images[@]} ; do
  docker pull $url/$imagename
  docker tag $url/$imagename k8s.gcr.io/$imagename
  docker rmi -f $url/$imagename
done
#��images.sh �������������--------end-----
chmod 777 ./image.sh
./image.sh

```




### **4.5��pod���ڵĽڵ���ˣ�pod��Ȼ��running״̬����û��ת�Ƶ��𵽽ڵ�**

https://kubernetes.io/docs/concepts/nodes/node/

### **4.6��ubuntu��ȫж��docker**

https://www.cnblogs.com/shmily3929/p/12085163.html

### **4.7����װ�ض��汾docker**

https://www.runoob.com/docker/ubuntu-docker-install.html

```
#��ͨ����������汾��Ϣ
apt-cache madison docker-ce
#��װָ���汾docker
sudo apt-get install docker-ce=5:18.09.7~3-0~ubuntu-xenial docker-ce-cli=5:18.09.7~3-0~ubuntu-xenial containerd.io
```

### **4.8����װָ���汾k8s**

```
sudo apt install -y kubelet=1.14.2-00 kubeadm=1.14.2-00 kubectl=1.14.2-00
```

### **4.9��**cni��ַ��podIp����һ����

����cni0�����������ַ��10.244.1.1�������뱨���е�10.244.2.1��һ�£������Ϊ10.244.2.1������������񣬻ص�master������������������

��ʹ��nmtui��Ȼ��cni�ĵ�ַ�ĵ�

```
systemctl restart network
```

Ҳ�ɽ�10.244.1.1���Ǹ�����ɾ���������Լ��ؽ���

Ҳ�ɽ�10.244.1.1���Ǹ�����ɾ���������Լ��ؽ���

### **4.10���ڽڵ��в���pingͨ����ip**

�ο���ַ��https://www.cnblogs.com/cxbhakim/p/9626507.html
1��ping �ڵ�
2���鿴 flanet �������鿴dns �鿴proxy
3����������linux���еײ��iptables��������node�Ϸֱ�ִ�У�

```
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -F
iptables -L -n
```

### **4.11 ��ʼ��ָ���汾k8s**

```
kubeadm init --apiserver-advertise-address 192.168.2.178 --pod-network-cidr=10.244.0.0/16 --kubernetes-version=v1.14.2
```

4.12 ��ping��ͬ�ٶ�

```
#1���༭Linux�е����������ļ�
	vi /etc/sysconfig/network-scripts/ifcfg-ens33
#ע ���������ļ������ܻ��в�ͬ�������뵽ifcfgʱ����������������tab������ȡ��ʾ�������ҵĻ��� Ϊ ifcfg-ens33

#�����滻���£�
    TYPE=��Ethernet��
    BOOTPROTO=��static��
    NAME=��ens33��
    UUID=��1f093d71-07de-4ca5-a424-98e13b4e9532��
    DEVICE=��ens33��
    ONBOOT=��yes�� #�����豸��������
    IPADDR=��192.168.126.110��
    NETMASK=��255.255.255.0�� #��������
    GATEWAY=��192.168.126.1�� #����IP
    DNS1= 8.8.8.8
    DNS2=8.8.8.4

#3�������������
����service network restart

#4��DNS�ļ�����
    vi /etc/resolv.conf
    nameserver 8.8.8.8
    nameserver 8.8.4.4
```

### 4.12��kubelet cgroup driver: "cgroupfs" is different from docker cgroup driver: "systemd

?    	https://www.cnblogs.com/hongdada/p/9771857.html