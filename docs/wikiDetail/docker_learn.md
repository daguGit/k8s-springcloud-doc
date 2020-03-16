# Docker

## 1.  Docker���

### 1.1.  ����

?		��������ά֮����Ϊ������ͬ�����µ�ì��

?		��Ⱥ������ÿ̨����������ͬ��Ӧ��

?		DevOps(Development and Operations)

### 1.2.  ���

?		Docker��һ����Դ��Ӧ���������棬�ÿ����߿��Դ�����ǵ�Ӧ���Լ���������һ������ֲ�������У�Ȼ�󷢲����κ����е�Linux�����ϣ�Ҳ����ʵ�����⻯����������ȫʹ��ɳ����ƣ��໥֮�䲻�����κνӿڡ�

?		Docker���������ȵ��������ƽ̨��������Ա���� Docker ��������Э������ʱ�����ҵĻ����Ͽ����������������⡣��ά��Ա���� Docker �����ڸ��������в������к͹���Ӧ�ã���ø��õļ����ܶȡ���ҵ���� Docker ���Թ������ݵ���������ܵ����Ը�����ٶȡ����ߵİ�ȫ�ԺͿɿ�������Ϊ Linux �� Windows Server Ӧ�÷����¹��ܡ�

### 1.3.  Docker�ŵ�

?		�򻯳��� Docker �ÿ����߿��Դ�����ǵ�Ӧ���Լ���������һ������ֲ�������У�Ȼ�󷢲����κ����е� Linux�����ϣ������ʵ�����⻯��Docker�ı������⻯�ķ�ʽ��ʹ�����߿���ֱ�ӽ��Լ��ĳɹ�����Docker�н��й����������Ѿ��� Docker��������ƣ���ȥ��Ҫ�������������ܵ� ������Docker�����Ĵ����£�ֻ��Ҫ����������

?		����ѡ��־�֢�� �������ѡ��־�֢����������ߡ�Docker ���� �����ľ��ᣡ���� Docker ����Docker�����а��������л��������ã����� Docker ���Լ򻯲������Ӧ��ʵ������������ Web Ӧ�á���̨Ӧ�á����ݿ�Ӧ�á�������Ӧ�ñ��� Hadoop ��Ⱥ����Ϣ���еȵȶ����Դ����һ��������

?		��ʡ��֧�� һ���棬�Ƽ���ʱ��������ʹ�����߲���Ϊ��׷��Ч�������ø߶��Ӳ����Docker �ı��˸����ܱ�Ȼ�߼۸��˼ά���ơ�Docker ���ƵĽ�ϣ����ƿռ�õ�����ֵ����á����������Ӳ����������⣬Ҳ�ı������⻯

�ķ�ʽ��

## 2.  Docker �ܹ�

Dockerʹ��C/S�ܹ���Clientͨ���ӿ���Server����ͨ��ʵ�������Ĺ��������кͷ�������ͼ��

![img](file:///C:\Users\ADMINI~1\AppData\Local\Temp\msohtmlclip1\01\clip_image002.jpg)

### 2.1.  Host����������

��װ��Docker���򣬲�������Docker daemon��������

 

 **Docker daemon(Docker �ػ�����)��**

?		�������������ϣ�Docker�ػ����̣��û�ͨ��Docker client(Docker����)��Docker daemon������

 **Images(����)��**

?		�������������õ�ģ�壬�������������ģ�һ��������Դ������������

 **����ֲ�ṹ��**

![img](file:///C:\Users\ADMINI~1\AppData\Local\Temp\msohtmlclip1\01\clip_image004.jpg)

 λ���²�ľ����Ϊ������(Parent Image)����ײ�ĳ�Ϊ��������(Base Image)��

 ���ϲ�Ϊ���ɶ�д���㣬���µľ�Ϊ��ֻ�����㡣

 AUFS:

  - advanced multi-layered uni?cation ?lesystem���߼����ͳһ�ļ�ϵͳ
  - ����ΪLinux�ļ�ϵͳʵ�֡����Ϲ��ء�
  - AUFS��֮ǰ��UnionFS������ʵ��
  - Docker���ʹ��AUFS��Ϊ�����ļ�ϵͳ��
  - AUFS�ľ�����Ʒ��overlayFS����3.18��ʼ���ϲ���Linux�ں�
  - Docker�ķֲ㾵�񣬳���AUFS��Docker��֧��btrfs��devicemapper��vfs��

**Containers(����)**��
 Docker���������������һ���������һ������������������֮���໥���룬���һ���Ӱ�졣

### 2.2.  Docker Client���ͻ��ˣ�

Docker�����й��ߣ��û�����Docker Client��Docker daemon����ͨ�Ų����ؽ�����û���Ҳ����ʹ����������ͨ��Docker Api ��Docker daemonͨ�š�

### 2.3.  Registry���ֿ����ע�ᣩ

������Ͳֿ�(Repository)��Ϊһ̸��ʵ����Registry�Ͽ����ж���ֿ⣬ÿ���ֿ���Կ�����һ���û���һ���û��Ĳֿ���˶�����񡣲ֿ��Ϊ�˹����ֿ�(Public Repository)��˽�вֿ�(Private Repository)�����Ĺ����ֿ��ǹٷ���Docker Hub������Ҳ���簢���ơ�ʱ���Ƶȣ����Ը������û��ṩ�ȶ����ٵķ����û�Ҳ�����ڱ��������ڴ���һ��˽�вֿ⡣���û��������Լ��ľ���֮��Ϳ���ʹ�� push ������ϴ������л���˽�вֿ⣬�����´�������һ̨������ʹ���������ʱ��ֻ��Ҫ�Ӳֿ��� pull �����Ϳ����ˡ�

## 3.  Docker��װ

Docker �ṩ�������汾�������� (CE) ����ҵ�� (EE)��

### 3.1.  ����ϵͳҪ��

��Centos7Ϊ������Docker Ҫ�����ϵͳ����Ϊ64λ����centos�ں˰汾Ϊ3.1�����ϡ�

�鿴ϵͳ�ں˰汾��Ϣ��

```
uname -r
```

### 3.2.  ׼��

ж�ؾɰ汾��

```
yum remove docker docker-common docker-selinux docker-engine
yum remove docker-ce
```

ж�غ󽫱��� /var/lib/docker �����ݣ������������洢�������ȣ���

```
rm -rf /var/lib/docker
```

1.��װ���������

```
yum install -y yum-utils device-mapper-persistent-data lvm2
#��װǰ�ɲ鿴device-mapper-persistent-data��lvm2�Ƿ��Ѿ���װ
rpm -qa|grep device-mapper-persistent-data
rpm -qa|grep lvm2
```

2.����yumԴ

```
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
```

3.����yum���������

```
yum makecache fast
```

### 3.3.  ��װ

��װ���°汾docker-ce:

```
yum install docker-ce �Cy
#��װָ���汾docker-ce��ʹ����������鿴
yum list docker-ce.x86_64 --showduplicates | sort �Cr
# ��װ���֮�����ʹ������鿴
docker version
```

### 3.4.  ���þ������

����ʹ�ð����Ƶ���Ѿ�����ٷ���Ҳ����ʹ��������ʱ���ơ������Ƶ�

1.ע���¼��ͨ������[�����������](https://cr.console.aliyun.com/cn-hangzhou/repositories)

2.�鿴����̨���е�����������������Լ��ļ�������ַ

3.�ҵ�/etc/dockerĿ¼�µ�daemon.json�ļ���û����ֱ�� vi daemon.json

4.������������

```
#��д�Լ��ļ�������ַ
{
   "registry-mirrors": ["https://zfzbet67.mirror.aliyuncs.com"]
}
```

5.֪ͨsystemd���ش������ļ���

```
systemctl daemon-reload
```

6.����docker����

```
systemctl restart docker
```

## 4.  Docker���ò���

���� docker ���Բ鿴Docker�������÷������� docker COMMAND --help �鿴ָ��������ϸ�÷���

### 4.1.  �����ò���

**���Ҿ���**��

```
docker search �ؼ���
#����docker hub��վ�������ϸ��Ϣ
```

 **���ؾ���**��

```
docker pull ������:TAG
# Tag��ʾ�汾����Щ����İ汾��ʾlatest��Ϊ���°汾
```

 **�鿴����**

```
docker images
# �鿴�������о���
```

 **ɾ������**��

```
docker rmi -f ����ID���߾�����:TAG
# ɾ��ָ�����ؾ���
# -f ��ʾǿ��ɾ��
```

 **��ȡԪ��Ϣ**��

```
docker inspect ����ID���߾�����:TAG
# ��ȡ�����Ԫ��Ϣ����ϸ��Ϣ
```

### 4.2.  �������ò���

**����**��

```
docker run --name ������ -i -t -p �����˿�:�����˿� -d -v ����Ŀ¼:����Ŀ¼:ro ����ID������:TAG
# --name ָ�������������Զ��壬��ָ���Զ�����
# -i �Խ���ģʽ��������
# -t ����һ��α�նˣ��������У�ͨ��-it�����ʹ��
# -p ָ��ӳ��˿ڣ��������˿�ӳ�䵽�����ڵĶ˿�
# -d ��̨��������
# -v ָ����������Ŀ¼������Ŀ¼��Ĭ��Ϊrw��дģʽ��ro��ʾֻ��
```

**�����б�**��

```
docker ps -a -q
# docker ps�鿴�������е�����
# -a �鿴���������������С�δ���У�
# -q ֻ�鿴������ID
```

**��������**��

```
docker start ����ID��������
```

**ֹͣ����**��

```
docker stop ����ID��������
```

 **ɾ������**��

```
docker rm -f ����ID��������
# -f ��ʾǿ��ɾ��
```

**�鿴��־**:

```
docker logs ����ID��������
```

**����������������**��

```
docker exec -it ����ID���������� /bin/bash
# �����������е��������ҿ�������ģʽ�ն�
# /bin/bash�ǹ���д������������Ϊdocker��̨��������һ�����̣����������ͻ��˳����������ʾ��������������bash��
# Ҳ������docker exec�������е�����ִ������
```

 **�����ļ�**��

```
docker cp �����ļ�·�� ����ID��������:����·�� #�������ļ�������������
docker cp ����ID��������:����·�� �����ļ�·�� #�������ļ�������������
```

**��ȡ����Ԫ��Ϣ**��

```
docker inspect ����ID��������
```

### 4.3.  ����ʵ��

```
docker pull mysql:5.7
#��������Ҫ���ص�Ŀ¼
mkdir -p /my/mysql/conf
mkdir -p /my/mysql/data
mkdir -p /my/mysql/logs
#�����ļ� ���޸��ַ�
docker cp mysql:/etc/mysql/mysql.conf.d/mysqld.cnf /my/mysql/conf/
vi /my/mysql/conf/mysqld.conf
character-set-server=utf8
```

 

```
#������������
docker run \
--name mysql \
-p 3306:3306 \
-v /my/mysql/conf:/etc/mysql/mysql.conf.d/ \
-v /my/mysql/data:/var/lib/mysql \
-v /my/mysql/logs:/logs \
-e MYSQL_ROOT_PASSWORD=root \
-d mysql:5.7
```



## 5.  Docker ���ɾ���

��ʱ���Docker����ֿ������صľ���������Ҫ�����ǿ��Ի���һ���������񹹽�һ���Լ��ľ���

�������ַ�ʽ��

- ���¾���ʹ�� docker commit ����

- ��������ʹ�� docker build �����Ҫ����Docker?le�ļ�


### 5.1.  ���¾���

��ʹ�û������񴴽�һ��������Ȼ����������ݽ��и��ģ�Ȼ��ʹ�� docker commit �����ύΪһ���µľ�����tomcatΪ������

1.���ݻ������񣬴�������

```
docker run --name mytomcat -p 80:8080 -d tomcat
```

2.�޸���������

```
docker exec -it mytomcat /bin/bash
cd webapps/ROOT
rm -f index.jsp
echo hello world > index.html
exit
```

3.�ύΪ�¾���

```
docker commit -m="������Ϣ" -a="����" ����ID�������� ������:TAG
# ��:
# docker commit -m="�޸�����ҳ" -a="User01" mytomcat user01/tomcat:v1.0 
```

4.ʹ���¾�����������

```
docker run --name tom -p 8080:8080 -d user01/tomcat:v1.0
```

 

### 5.2.  Dockerfile��������

#### 5.2.1. ʲô��DockerFile

Docker?le is nothing but the source code for building Docker images

- Docker can build images automatically by reading the instructions from a Docker?le

- A Docker?le is a text document that contains all the commands a user could call on the command lineto assemble an image

- Using docker build users can create an automated build that executes several command-line instructionsin succession


![img](file:///C:\Users\ADMINI~1\AppData\Local\Temp\msohtmlclip1\01\clip_image005.jpg)

#### 5.2.2. Dockerfile��ʽ

- Format��
    - \#Comment
    - INSTRUCTION arguments
- The instruction is not case-sensitive
    - However,convention is for them to be UPPERCASE to distinguish them from arguments more easily
- Docker runs instructions in a Docker?le in order
- The ?rst instruction must be 'FROM' in order to specify the Base Image from which you are building



#### 5.2.3. ʹ��Dockerfile��������ʵ��

һ��׼��

1.�����springboot��Ŀ����ɿ�ִ��jar��

2.��jar���ϴ���Linux������

��������

1.��jar��·���´���Docker?le�ļ� vi Dockerfile 

```
# ָ���������񣬱���û�л��dockerHub pull����
FROM java:8
#����
MAINTAINER user01
#�ѿ�ִ��jar�����Ƶ���������ĸ�Ŀ¼��
ADD luban.jar /luban.jar
# ����Ҫ��¶�Ķ˿ڣ���Ҫʹ�ö˿ڣ���ִ��docker run����ʱʹ��-p��Ч
EXPOSE 80
# �ھ�������Ϊ������ִ�е�����
ENTRYPOINT ["java","-jar","/luban.jar"]
```

2.ʹ�� docker build ��������񣬻����﷨

```
docker build -t user01/mypro:v1 .
# -fָ��Dockerfile�ļ���·��
# -tָ���������ֺ�TAG
# .ָ��ǰĿ¼������ʵ������Ҫһ��������·��
```

��������

�����Լ���SpringBoot����

```
docker run --name pro -p 80:80 -d ������:TAG
```

#### 5.2.4. Dockerfile��������

##### 5.2.4.1.      FROM

FROMָ��������Ҫ��һ�����ұ���ΪDocker?le�ļ���ƪ�ĵ�һ����ע���У�����Ϊ�����ļ���������ָ���������񣬺�����ָ�������ڴ˻��������ṩ�����л�����

�����������������κο��þ���Ĭ�������docker build��ӱ��زֿ���ָ���ľ����ļ�����������ھͻ��Docker Hub����ȡ

�﷨��

```
FROM <image>
FROM <image>:<tag>
FROM <image>@<digest>
```

##### 5.2.4.2.      MAINTAINER(depreacted)

Docker?le���������ṩ�ı�����ϸ��Ϣ

Docker?le������MAINTAINER���ֵ�λ�ã������Ƽ��ŵ�FROMָ��֮��

�﷨��

```
MAINTAINER <name>
```

name�������κ��ı���Ϣ��һ�����������ƻ�������

##### 5.2.4.3.      LABEL

 ������ָ������Ԫ����

�﷨��

```
LABEL <key>=<value> <key>=<value> <key>=<value>..
```

һ��Docker?le����д���LABEL�����ǲ��Ƽ���ô����Docker?leÿһ��ָ�������һ�㾵�����LABEL̫������ʹ��\���Ż��С������ľ����̳л��������LABEL�����һ�ȥ���ظ��ģ������ֵ��ͬ��������ֵ�Ḳ��ǰ���ֵ��

##### 5.2.4.4.      COPY

���ڴ������������ļ����������¾����ļ�

�﷨��

```
COPY <src>...<dest>
COPY ["<src>",..."<dest>"]
# <src>��Ҫ���Ƶ�Դ�ļ�����Ŀ¼������ʹ��ͨ���
# <dest>��Ŀ��·���������ڴ�����image���ļ�ϵͳ·��������<dest>ʹ�þ���·��������COPYָ������WORKDIRΪ
����ʼ·��
```

 ע�⣺������·�����пհ��ַ���ͨ����ʹ�õڶ��ָ�ʽ

����

- <src> ������build�������е�·�����������丸Ŀ¼�е��ļ�
- ��� <src> ��Ŀ¼�������ڲ��ļ�����Ŀ¼�ᱻ�ݹ鸴�ƣ��� <src> Ŀ¼�����ᱻ����

- ���ָ���˶�� <src> ������ <src> ��ʹ����ͨ������� <dest> ������һ��Ŀ¼���������/���Ž�β

- ��� <dest> �����ڣ����ᱻ�Զ������������丸Ŀ¼·��


##### 5.2.4.5.      ADD

�����÷���COPYָ��һ����ADD֧��ʹ��TAR�ļ���URL·��

�﷨��

```
ADD <src>...<dest>
ADD ["<src>",..."<dest>"]
```

����

- ��COPY������ͬ

- ��� <src> ΪURL���� <dest> û����/��β���� <src> ָ�����ļ��������ص� <dest>

- ��� <src> ��һ������ϵͳ��ѹ����ʽ��tar�ļ�������չ����һ��Ŀ¼������ͨ��URL��ȡ��tar�ļ������Զ�չ��

- ��� <src> �ж����ֱ�ӻ���ʹ����ͨ���ָ�������Դ���� <dest> ������Ŀ¼������/��β


##### 5.2.4.6.       WORKDIR

����ΪDocker?le�����е�RUN��CMD��ENTRYPOINT��COPY��ADDָ���趨����Ŀ¼��ֻ��Ӱ�쵱ǰWORKDIR

֮���ָ�

�﷨��

```
WORKDIR <dirpath>
```

��Docker?le�ļ��У�WORKDIR���Գ��ֶ�Σ�·�����������·�����������������ǰһ��WORKDIRָ��ָ����·�����⣬WORKDIR������ENVָ������ı���

##### 5.2.4.7.       VOLUME

�����������ص㣬���Թ����������ϵľ�������������ϵľ�

�﷨��

```
VOLUME <mountpoint>
VOLUME ["<mountpoint>"]
```

 ����ָ�����������е�Ŀ¼�����������ص�Ŀ¼���Զ����ɵ�

##### 5.2.4.8.       EXPOSE

���ڸ�������ָ��Ҫ�����Ķ˿���ʵ�ֺ��ⲿͨ��

�﷨��

```
EXPOSE <port>[/<protocol>] [<port>[/<protocol>]...]
```

<protocol> ����ָ�������Э�飬������TCP����UDP��Ĭ����TCPЭ��

EXPOSE����һ����ָ������˿ڣ����磺 EXPOSE 80/tcp 80/udp

##### 5.2.4.9.      ENV

����������������Ҫ�Ļ������������ҿ��Ա�Docker?le�ļ���λ����������ָ��(��ENV��ADD��COPY��)�����ã����ø�ʽ��$variable_name����${variable_name}

�﷨��

```
ENV <key> <value>
ENV <key>=<value>...
```

��һ�ָ�ʽ�У� <key> ֮����������ݶ��ᱻ��Ϊ <value> ����ɲ��֣�����һ��ֻ������һ������

�ڶ��ָ�ʽ����һ�����ö����������� <value> �����пո����ʹ��\����ת����߶� <value> �����Ž��б�ʶ��

����\Ҳ������������

##### 5.2.4.10.     ARG

�÷�ͬENV

�﷨��

```
ARG <name>[=<default value>]
```

ָ��һ��������������docker build���������ʱ��ʹ�� --build-arg <varname>=<value> ��ָ������

##### 5.2.4.11.     RUN

����ָ��docker build����������ָ��������

�﷨��

```
RUN <command>
RUN ["<executable>","<param1>","<param2>"]
```

��һ�ָ�ʽ����Ĳ���һ����һ��shell����� /bin/sh -c ��������

�ڶ��ָ�ʽ�еĲ�����һ��JSON��ʽ�����飬���� <executable> ��Ҫ���е���������Ǵ��ݸ������ѡ����߲������������ָ�ʽ������ /bin/sh -c ���������Գ�����shell����������滻��ͨ����滻������У���������е���������shell���ԣ������滻���������µĸ�ʽ

RUN ["/bin/bash","-c","<executable>","<param1>"]

##### 5.2.4.12.    CMD

��������ʱ���е�����

�﷨��

```
CMD <command>
CMD ["<executable>","<param1>","<param2>"]
CMD ["<param1>","<param2>"] 
```

ǰ�����﷨��RUN��ͬ

�������﷨����ΪENTRYPOINTָ���ṩĬ�ϲ���

RUN��CMD����

- RUNָ�������ھ����ļ����������У�CMD�������ڻ���Docker?le���������¾����ļ�����Ϊһ��������ʱ��
- CMDָ�����ҪĿ�����ڸ�����������ָ��Ĭ��Ҫ���еĳ����������н���������Ҳ����ֹ��������CMD������Ա�docker run��������ѡ�������
- Docker?le�п��Դ��ڶ��CMDָ�����ֻ�����һ������Ч


##### 5.2.4.13.    ENTRYPOINT

������CMDָ��ܣ����ڸ�����ָ��Ĭ�����г���

�﷨��

```
ENTRYPOINT<command>
ENTRYPOINT["<executable>","<param1>","<param2>"]
```

��CMD��ͬ����ENTRYPOINT�����ĳ��򲻻ᱻdocker run����ָ���Ĳ��������ǣ����ң���Щ�����в����ᱻ�����������ݸ�ENTRYPOINTָ���ĳ���(���ǣ�docker run�����--entrypoint�������Ը���ENTRYPOINT)

docker run�����Ĳ����Ḳ��CMDָ������ݲ��Ҹ��ӵ�ENTRYPOINT���������Ϊ�����ʹ��.ͬ����Docker?le�п��Դ��ڶ��ENTRYPOINTָ�����ֻ�����һ������Ч.

Docker?le���������CMD����ENTRYPOINT������CMD��һ��������ִ�������ô˭�����˭��Ч

##### 5.2.4.14.     ONBUILD

������Docker?le�ж���һ��������

�﷨��

```
ONBUILD <instruction>
```

Docker?le�������������ļ��������ļ�Ҳ���Ե����ǻ�����������һ��Docker?le����FROMָ��Ĳ���

�ں������Docker?le�е�FROMָ���ڹ��������б�ִ�е�ʱ�򣬻ᴥ���������������ONBUILDָ��

ONBUILD��������Ƕ�ף�ONBUILD���ᴥ��FROM��MAINTAINERָ��

��ONBUILDָ����ʹ��ADD��COPYҪС�ģ���Ϊ�¹��������е���������ȱ��ָ����Դ�ļ���ʱ���ʧ��

## 6.  ���ؾ��񷢲���������

��ʱ����Ҫ���������ϰ��ʹ���Լ�����ľ��񣬿���ע��˽�вֿ⣬�����Ƽ�ʹ�ð�����

���裺

1.��¼�����������������https://cr.console.aliyun.com/cn-hangzhou/repositories

2.���������͵�������

```
# ��¼�����Ƶ�docker�ֿ�
$ sudo docker login --username=[�û���] registry.cn-hangzhou.aliyuncs.com
# ����ָ�������tag������ĳ���ֿ�
$ sudo docker tag [����ID] registry.cn-hangzhou.aliyuncs.com/user01/user01:[����汾��]
# ���������͵��ֿ�
$ sudo docker push registry.cn-hangzhou.aliyuncs.com/user01/user01:[����汾��]
```

3.��ȡ����

```
docker pull registry.cn-hangzhou.aliyuncs.com/coldest7/mytom:v1
```

## 7.  Docker����

Docker����ͨ���ⲿ�������������������ķ�ʽ���ṩ�������

��װDockerʱ�����Զ���װһ��Docker������Ϊdocker0������Docker��������������������ͨ�ţ�����Ϊ172.0.0.1��

Docker���������������ĸ��ɳ�У�Sandbox�������磨Network�����˵㣨Endpoint����

- ɳ�У��ṩ����������������ջ��Ҳ���˿��׽��֡�IP·�ɱ�����ǽ�����ݡ������������������������磬�γ�����ȫ�������������绷����

- ���磬�������ΪDocker�ڲ������������������ڵĲ������໥�ɼ����ܹ�����ͨѶ��Docker����������������������Ǵ��ڸ����ϵ�ģ���Ŀ����Ҫ���γ�������İ�ȫͨѶ������

- �˵㣬λ���������������ǽ֮�ϵĶ�����ҪĿ�����γ�һ�����Կ��Ƶ�ͻ�Ʒ�յ����绷���ĳ���ڡ��������Ķ˵�������Ķ˵��γ���Ժ󣬾���ͬ��������֮�������������ܹ��������ݴ����ˡ�


### 7.1.  Docker����������

Docker������������ʱ��ᴴ���������磬bridge��host��none������һ�ֹ���������ģʽcontainer

 **Bridge**

�Ž�ģʽ����Ҫ��������ͨ�ŵģ�docker����Ĭ�ϵ�����ʹ�õľ���bridge��

ʹ��bridgeģʽ���������Զ�����������

```
# ����������������
docker run --name t1 --network bridge -h [�Զ���������] -it --rm busybox
# �Զ���DNS
docker run --name t1 --network bridge --dns 114.114 -it --rm busybox
# ��host�ļ����һ��
docker run --name t1 --network bridge --add-host [hostname]:[ip] -it --rm busybox
```

 **Host**

 host���͵�������������������˼���󶨵���������������������ڲ�ʹ�õĶ˿�ֱ�Ӱ��������϶�Ӧ�Ķ˿ڣ��������������û��ʹ�ö˿ڣ�����Ӱ�졣

**None**

��ĳ����������˵��noneӦ���㲻�������ˣ���Ϊ����ʹ���κ����磬���γ�һ��������������

**container**

 ��������һ��������network namespace����hostģʽ��ֻ࣬�����ﲻ��ʹ�����������磬����ʹ�õ���������.

## 8.  ���Ŷ˿�

Docker0ΪNAT�ţ���������һ���õ���˽�������ַ

��docker run����ʹ��-pѡ���ʵ�ֶ˿�ӳ�䣬�����ֶ���ӹ���

- -p ѡ���ʹ��

    - -p <containerPort>

        - ��ָ���������˿�ӳ�䵽�������е�ַ��һ����̬�˿�

    - -p <hostPort>:<containerPort>

        - �������˿� <containerPort> ӳ�䵽ָ���������˿� <hostPort>

    - -p <ip>::<containerPort>

        - ��ָ���������˿� <containerPort> ӳ�䵽����ָ�� <ip> �Ķ�̬�˿�

    - -p <ip>:<hostPort>:<containerPort>
- ��ָ���������˿� <containerPort> ӳ��������ָ�� <ip> �Ķ˿� <hostPort>
  
 - ��̬�˿�ָ����˿ڣ�����ʹ��docker port����鿴����ӳ����

- -P ��¶���ж˿ڣ����ж˿�ָ��������ʱEXPOSE�Ķ˿ڣ�

 

�Զ���docker0�ŵ�����������Ϣ��/etc/docker/daemon.json�ļ�

```
{
 "bip": "192.168.1.5/24",
 "fixed-cidr": "10.20.0.0/16",
 "fixed-cidr-v6": "2001:db8::/64",
 "mtu": 1500,
 "default-gateway": "10.20.1.1",
 "default-gateway-v6": "2001:db8:abcd::89",
 "dns": ["10.20.1.2","10.20.1.3"]
}
```

����ѡ��Ϊbip����bridge ip֮�⣬����ָ��docker0�������IP��ַ������ѡ���ͨ���˵�ַ����ó�

Զ������

�����Զ������

```
docker network create -d bridge --subnet "172.26.0.0/16" --gateway "172.26.0.1" mybr0
```



## 9.  Docker compose

����һ�ڿ������˽⵽����ʹ��һ��Docker?leģ���ļ������ٹ���һ���Լ��ľ�������ΪӦ��������������ƽʱ������ʱ�����ǻ������������Ҫ���������ʹ�õ�������������ݿ��������WebӦ�õȵȡ���������£�ÿ�ζ�Ҫһ��һ���������������������鷳����������Docker Compose�����ˡ�

### 9.1.  Dockercompse���

Compose�������ǡ���������ж��Docker������Ӧ�á���ʹ��Compose���������һ�������ļ���yaml��ʽ����������Ӧ�õķ���Ȼ��ʹ��һ��������ɴ������������������õ����з���

Compose��������Ҫ���

- ���� (service)��һ��Ӧ�õ�������ʵ���Ͽ��԰�������������ͬ���������ʵ����

- ��Ŀ (project)����һ�������Ӧ��������ɵ�һ������ҵ��Ԫ���� docker-compose.yml�ļ��ж��塣


### 9.2. Dockercompse��װ

Compose֧����ƽ̨Windows��Mac��Linux����װ��ʽ���в�ͬ��������ʹ�õ���Linuxϵͳ������ϵͳ��װ����

���Բο��ٷ��ĵ��Ϳ�ԴGitHub���ӣ�

Docker Compose�ٷ��ĵ����ӣ�https://docs.docker.com/compose

Docker Compose GitHub���ӣ�https://github.com/docker/compose

Linux�������ְ�װ������Compose��Ŀ����Pythonд�ģ�����ʹ��Python-pip��װ��Ҳ����ͨ��GitHub���ض������ļ����а�װ��

**ͨ��Python-pip��װ**

1.��װPython-pip

```
yum install -y epel-release
yum install -y python-pip
```

2.��װdocker-compose

```
pip install docker-compose
```

3.��֤�Ƿ�װ

```
docker-compose version
```

4.ж��

```
pip uninstall docker-compose
```

**ͨ��GitHub�������ذ�װ**

 

��ROOT�û��ǵü�sudo

1.ͨ��GitHub��ȡ�������ӣ������汾��ַ��https://github.com/docker/compose/releases

```
curl -L "https://github.com/docker/compose/releases/download/1.23.2/docker-compose-$(uname-s)-$(uname -m)" -o /usr/local/bin/docker-compose 
```

2.�������������ļ���ִ�е�Ȩ��

```
chmod +x /usr/local/bin/docker-compose
```

3.����û�������������������ӣ�����:

```
ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
```

4.��֤�Ƿ�װ

```
docker-compose version
```

5.ж��

����Ƕ����ư���ʽ��װ�ģ�ɾ���������ļ����ɡ�

```
rm /usr/local/bin/docker-compose
```

��ʵ��

 

Compose��ʹ�÷ǳ��򵥣�ֻ��Ҫ��дһ��docker-compose.yml��Ȼ��ʹ��docker-compose ����������ɡ�

docker-compose.yml���������������ã���docker-compose ���������˶������Ĳ���

1.����ʹ��һ��΢������Ŀ������һ���򵥵����ӣ����ȴ���һ��compose�Ĺ���Ŀ¼��Ȼ�󴴽�һ��eureka�ļ��У�����ſ�ִ��jar���ͱ�дһ��Docker?le�ļ���Ŀ¼�ṹ���£�

```
compose
	eureka
		Dockerfile
		eureka-server-2.0.2.RELEASE.jar
```

2.��composeĿ¼����ģ���ļ�docker-compose.yml�ļ���д����������

```
version: '1'
services:
	eureka:
		build: ./eureka
		ports:
		  - 3000:3000
		expose:
          - 3000 
```



### 9.3.  DockerCompose��������

##### 9.3.1.1.      image

ָ���������ƻ��߾���id������þ����ڱ��ز����ڣ�Compose�᳢��pull������

ʾ����

```
image: java:8
```

##### 9.3.1.2.      build

ָ��Docker?le�ļ���·����������һ��·�������磺build: ./dir

Ҳ������һ����������ָ��Docker?le�Ͳ��������磺

```
build: context: ./dir docker?le: Docker?le-alternate args: buildno: 1
```

##### 9.3.1.3.      command

��������������Ĭ��ִ�е����

ʾ����

```
command: bundle exec thin -p 3000
```

Ҳ������һ��list��������Docker?le�ܵ�CMDָ���ʽ���£�

```
command: [bundle, exec, thin, -p, 3000]
```

##### 9.3.1.4.      links

���ӵ����������е�����������ָ���������ƺ����ӵı���ʹ��SERVICE:ALIAS ����ʽ������ָֻ���������ƣ�ʾ

����

```
web: links: - db - db:database �C redis
```

##### 9.3.1.5.      external_links

��ʾ���ӵ�docker-compose.yml�ⲿ����������������Compose������������ر��Ƕ�����Щ�ṩ����������ͬ

���񡣸�ʽ��links���ƣ�ʾ����

```
external_links: - redis_1 - project_db_1:mysql - project_db_1:postgresql
```

##### 9.3.1.6.      ports

��¶�˿���Ϣ��ʹ�������˿�:�����˿ڵĸ�ʽ�����߽���ָ�������Ķ˿ڣ���ʱ�������������ָ���˿ڣ���������docker run -p ��ʾ����

```
ports:
    "3000"
    "3000-3005"
    "8000:8000"
    "9090-9091:8080-8081"
    "49100:22"
    "127.0.0.1:8001:8001"
    "127.0.0.1:5000-5010:5000-5010"
```



##### 9.3.1.7.      expose

��¶�˿ڣ�ֻ���˿ڱ�¶�����ӵķ��񣬶�����¶����������ʾ����

```
expose: - "3000" - "8000"
```

##### 9.3.1.8.      volumes

�����·�����á���������������·�� ��HOST:CONTAINER�� ����Ϸ���ģʽ ��HOST:CONTAINER:ro����ʾ����

volumes:

Just specify a path and let the Engine create a volume

- /var/lib/mysql


Specify an absolute path mapping

- /opt/data:/var/lib/mysql


Path on the host, relative to the Compose ?le

- ./cache:/tmp/cache


User-relative path

- ~/con?gs:/etc/con?gs/:ro

Named volums

- datavolume:/var/lib/mysql


##### 9.3.1.9.      volumes_from

����һ����������������ؾ�����ָ��ֻ�����߿ɶ�д���������ģʽû��ָ������Ĭ���ǿɶ�д��ʾ����

volumes_from:

- service_name

- service_name:ro

- container:container_name

- container:container_name:rw


##### 9.3.1.10.    environment

���û�������������ʹ����������ֵ����ַ�ʽ��ֻ��һ��key�Ļ�����������������Compose�Ļ������ҵ���Ӧ��

ֵ���������ڼ��ܵĻ�������������ֵ��ʾ����

```
environment: RACK_ENV: development SHOW: 'true' SESSION_SECRET: environment: -
RACK_ENV=development - SHOW=true - SESSION_SECRET
```



##### 9.3.1.11.    env_?le

���ļ��л�ȡ��������������Ϊ�������ļ�·�����б����ͨ�� docker-compose -f FILE ָ����ģ���ļ�����env_?le ��·�������ģ���ļ�·��������б��������� environment ָ���ͻ������envirment Ϊ׼��ʾ����

```
env_?le: .env env_?le: - ./common.env - ./apps/web.env - /opt/secrets.env
```

##### 9.3.1.12.    extends

�̳���һ�����񣬻������еķ��������չ��

##### 9.3.1.13.    net

��������ģʽ��ʾ����

```
net: "bridge" net: "host" net: "none" net: "container:[service name or container name/id]"
```

##### 9.3.1.14.    dns

����dns��������������һ��ֵ��Ҳ������һ���б�ʾ����

```
dns: 8.8.8.8 dns: - 8.8.8.8 - 9.9.9.9
```



##### 9.3.1.15.    dns_search

����DNS�������򣬿�����һ��ֵ��Ҳ������һ���б�ʾ����

```
dns_search: example.com dns_search: - dc1.example.com - dc2.example.com
```

##### 9.3.1.16.    ����

docker-compose.yml ���кܶ�����������Բο�docker-compose.yml�ļ��ٷ��ĵ���

[https://docs.docker.com/compose/compose-?le/](https://docs.docker.com/compose/compose-file/)

### 9.4.  ʹ��DockerCompose����ʵ��

ʹ��docker-composeһ��������������΢����:eureka����(eureka-server-2.0.2.RELEASE.jar)��user����(user-2.0.2.RELEASE.jar)��power����(power-2.0.2.RELEASE.jar)

1.����һ������Ŀ¼��docker-composeģ���ļ�

2.����Ŀ¼�´��������ļ���eureka��user��power�����ֱ𹹽�����������ľ����ļ�

��eureka��Docker?leΪ��:

```
# ��������
FROM java:8
# ����
MAINTAINER user01
# �ѿ�ִ��jar�����Ƶ���������ĸ�Ŀ¼��
ADD eureka-server-2.0.2.RELEASE.jar /eureka-server-2.0.2.RELEASE.jar
# ����Ҫ��¶�Ķ˿ڣ���Ҫʹ�ö˿ڣ���ִ��docker run����ʱʹ��-p��Ч
EXPOSE 3000
# �ھ�������Ϊ������ִ�е�����
ENTRYPOINT ["java","-jar","/eureka-server-2.0.2.RELEASE.jar"]
```

 

Ŀ¼�ļ��ṹ��

```
compose
	docker-compose.yml
	eureka
		Dockerfile
		eureka-server-2.0.2.RELEASE.jar
	user
		Dockerfile
		user-2.0.2.RELEASE.jar
	power
		Dockerfile
		power-2.0.2.RELEASE.jar
```

3.��дdocker-composeģ���ļ���

```
version: '1'
services:
  eureka:
	image: eureka:v1
	ports:
      - 8080:8080
  user:
    image: user:v1
    ports:
      - 8081:8081
  power:
    image: power:v1
    ports:
      - 8082:8082
```

4.����΢���񣬿��Լ��ϲ���-d��̨����

```
docker-compose up -d
```

