# RabbitMq ѧϰ�ʼ�

## һ����Ϣ�м������&ΪʲôҪʹ����Ϣ�м��

 ������java�������ӣ� ����ȷ� ���ǿͻ��˷���һ���µ����������ϵͳ��order������ϵͳ������

 һ����������ǵĿ��ϵͳ��������Ҫ���Ŀ���ˣ� ���Ѿ��µ��ˣ� ��� ÿһ���������Ƕ����Կ���һ����Ϣ�� ���� ���ǿͻ�����Ҫ�ȴ�����ϵͳ������������Ϣ�Ĵ��������ҵ�����û���µ��ɹ��� ���� ����ϵͳ����Ҫ֪�����ϵͳ������Ϣ�Ĵ������ ��Ϊ����������û�иĶ��ɹ��� �Ҷ����������ˣ� ��Ϊ���������˶������³ɹ��ˣ� ��ȥ���Ŀ�棬 ���������ĳ�BUG�� ���ǿ��ϵͳ�����⣬ ���BUG����Ӱ�충��ϵͳ����������������Ļ��� ��ô���Ǿ��ܷ��� **�����û����͵�������Ϣ���¶�������** **����Ҫͬ���ģ�����Ҫ֪���������** **�������͸�������Ϣ���ǿ����첽�ģ��Ҳ���֪�����浽�׸���û��** **��ֻ��֪ͨ������߳ɹ�����һ��������**

��ô������ǻ���ԭ���ķ�ʽȥʵ���������Ļ��� ��ô�������������

<img src="C:\Users\Administrator\Desktop\md\RabbitMq\p1.png" style="zoom:67%;" />



�ǿ�����ͬѧ˵�ˣ� ���Ƕ���ϵͳ�����߳�ȥ���ʿ��ϵͳ���ͺ�����

<img src="C:\Users\Administrator\Desktop\md\RabbitMq\p2.png" style="zoom:67%;" />

 ʹ���̳߳ؽ�� ȷʵ���ԣ� ����Ҳ������ȱ�㣬 ��ô ������ô�����������������أ�

<img src="C:\Users\Administrator\Desktop\md\RabbitMq\p3.png" style="zoom:67%;" />



�������ͼ�����Ļ��� ��ô �����Ϣϵͳ�� �������ǵ���Ϣ�м����



## ����RabbitMq����&AMQP����

����:���Ǹոս�����ʲô����Ϣ�м���� ��ôRabbitMq���Ƕ�����Ϣ�м����һ��ʵ�֣������ϻ��кܶ�ܶ�ʵ�֣� ����RabbitMq��ActiveMq��ZeroMq��kafka���Լ����￪Դ��RocketMQ�ȵ� ���������ҪѧϰRabbitMq ��



### 2.1 AMQP

 <img src="C:\Users\Administrator\Desktop\md\RabbitMq\p4.png" style="zoom:67%;" />

 �������ðٶȵ�һ�仰 �ټ����ҵ���⣺ AMQP ��ʵ��Httpһ�� ����һ��Э�飬 ֻ���� Http��������紫��ģ� ��AMQP�ǻ�����Ϣ���е�

AMQP Э���еĻ������

-  **Broker**: ���պͷַ���Ϣ��Ӧ�ã������ڽ�����Ϣ�м����ʱ����˵����Ϣϵͳ����Message Broker��


-  **Virtual host**: ���ڶ��⻧�Ͱ�ȫ������Ƶģ���AMQP�Ļ���������ֵ�һ������ķ����У������������е�namespace����������ͬ���û�ʹ��ͬһ��RabbitMQ server�ṩ�ķ���ʱ�����Ի��ֳ����vhost��ÿ���û����Լ���vhost����exchange��queue�ȡ�


-  **Connection**: publisher��consumer��broker֮���TCP���ӡ��Ͽ����ӵĲ���ֻ����client�˽��У�Broker����Ͽ����ӣ����ǳ���������ϻ�broker����������⡣

-  **Channel**: ���ÿһ�η���RabbitMQ������һ��Connection������Ϣ�����ʱ����TCP Connection�Ŀ������Ǿ޴�ģ�Ч��Ҳ�ϵ͡�Channel����connection�ڲ��������߼����ӣ����Ӧ�ó���֧�ֶ��̣߳�ͨ��ÿ��thread����������channel����ͨѶ��AMQP method������channel id�����ͻ��˺�message brokerʶ��channel������channel֮������ȫ����ġ�Channel��Ϊ��������Connection��������˲���ϵͳ����TCP connection�Ŀ�����


-  **Exchange**: message����broker�ĵ�һվ�����ݷַ�����ƥ���ѯ���е�routing key���ַ���Ϣ��queue��ȥ�����õ������У�direct (point-to-point), topic (publish-subscribe) and fanout (multicast)��


-  **Queue**: ��Ϣ���ձ��͵�����ȴ�consumerȡ�ߡ�һ��message���Ա�ͬʱ���������queue�С�


-  **Binding**: exchange��queue֮����������ӣ�binding�п��԰���routing key��Binding��Ϣ�����浽exchange�еĲ�ѯ���У�����message�ķַ����ݡ�


### 2.2 Exchange������:

####         direct :

?        �������͵Ľ�������·�ɹ����Ǹ���һ��routingKey�ı�ʶ��������ͨ��һ��routingKey����а� ����������������Ϣ��ʱ�� ָ��һ��routingKey ���󶨵Ķ��е�routingKey �������߷��͵�һ�� ��ô��������������Ϣ���͸���Ӧ�Ķ��С�

####         fanout:

?        �������͵Ľ�����·�ɹ���ܼ򵥣�ֻҪ�������˵Ķ��У� ���ͻ����Ϣ���͸���Ӧ���У���routingKeyû��ϵ��

####         topic:(��Ϊ*������ʼ���������ǹؼ��֣���������������滻����)

?         �������͵Ľ�����·�ɹ���Ҳ�Ǻ�routingKey�й� ֻ���� topic�����Ը���:��,#�� �ǺŴ������һ���ʣ�#������˺������е��ʣ� ��.��������ʶ��routingKey �Ҵ���ȷ� ���� �Ұ󶨵�routingKey �ж���A��B A��routingKey�ǣ���.user B��routingKey��: #.user

?        ��ô������һ����ϢroutingKey Ϊ�� error.user ��ô��ʱ 2�����ж��ܽ��ܵ��� �����Ϊ topic.error.user ��ô��ʱ�� ֻ��B�ܽ��ܵ���

####         headers:

?         ������͵Ľ����������õ�������·�ɹ��� ��routingKey�޹� ����ͨ���ж�header������ʶ��ģ� ������û��Ӧ�ó�������Ϊ��������������Ѿ���Ӧ���ˡ�

### 2.3 RabbitMQ

 MQ�� message Queue ����˼�� ��Ϣ���У� ���д�Ҷ�֪���� ������ݵ�һ�������� ��ŵ������Ƚ��ȳ��� ��Ϣ���У� ֻ�������ŵ���������Ϣ���ѡ�

 RabbitMq ��һ����Դ�� ����AMQPЭ��ʵ�ֵ�һ����������ҵ����Ϣ�м���������������Erlang�����򲢷���̣����Ա�д ���ڸ߲����Ĵ���������Ȼ�����ƣ��ͻ���֧�ַǳ�������ԣ�

?       Python

?       Java

?       Ruby

?       PHP

?       C#

?       JavaScript

?       Go

?       Elixir

?       Objective-C

?       Swift



### 2.4 ����MQ�Ա�

| ����                     | ActiveMQ                              | RabbitMQ                                           | RocketMQ                                                     | Kafka                                                        |
| ------------------------ | ------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| ����������               | �򼶣��� RocketMQ��Kafka ��һ�������� | ͬ ActiveMQ                                        | 10 �򼶣�֧�Ÿ�����                                          | 10 �򼶣������£�һ����ϴ��������ϵͳ������ʵʱ���ݼ��㡢��־�ɼ��ȳ��� |
| topic ��������������Ӱ�� |                                       |                                                    | topic  ���Դﵽ����/��ǧ�ļ������������н�С���ȵ��½������� RocketMQ ��һ�����ƣ���ͬ�Ȼ����£�����֧�Ŵ����� topic | topic �Ӽ�ʮ�����ٸ�ʱ���������������½�����ͬ�Ȼ����£�Kafka ������֤ topic ������Ҫ���࣬���Ҫ֧�Ŵ��ģ�� topic����Ҫ���Ӹ���Ļ�����Դ |
| ʱЧ��                   | ���뼶                                | ΢�뼶������  RabbitMQ ��һ���ص㣬�ӳ����        | ���뼶                                                       | ���뼶                                                       |
| ������                   | �ߣ��������Ӽܹ�ʵ�ָ߿���            | ͬ ActiveMQ                                        | �ǳ��ߣ��ֲ�ʽ�ܹ�                                           | �ǳ��ߣ��ֲ�ʽ��һ�����ݶ����������������崻������ᶪʧ���ݣ����ᵼ�²����� |
| ��Ϣ�ɿ���               | �нϵ͵ĸ��ʶ�ʧ����                  |                                                    | ���������Ż����ã���������  0 ��ʧ                           | ͬ RocketMQ                                                  |
| ����֧��                 | MQ ����Ĺ��ܼ����걸                 | ���� erlang ����������������ǿ�����ܼ��ã���ʱ�ܵ� | MQ ���ܽ�Ϊ���ƣ����Ƿֲ�ʽ�ģ���չ�Ժ�                      | ���ܽ�Ϊ�򵥣���Ҫ֧�ּ򵥵� MQ ���ܣ��ڴ����������ʵʱ�����Լ���־�ɼ������ģʹ�� |



## ����RabbitMQ����˲���



 �ڽ�����Ϣ�м����ʱ�����ᵽ�ġ���Ϣϵͳ�� ����������ڵ����⣺RabbitMq ��ͬredisһ�� ��Ҳ�ǲ���c/s�ܹ� �ɷ���� ��ͻ�����ɣ� �����������Ǽ�����ϲ������ķ����

�������Ǹոս��ܹ���RabbitMQ���������Erlang���Ա�д������������������Erlang���ԵĻ���

ע�⣺������ڹ����µ�RabbitMQ����˵Ļ� Erlang���Եİ汾����̫�ͣ� ��ȻҪж�ص��ɵ�ȥװ�µģ� ������������OTP21.0�汾ֱ�Ӵ��������ػ������ ������ֱ�����ϰٶ����̵ĵ�ַ(��Ϊ������������е���)

https://pan.baidu.com/s/1pZJ8l2f3omrgnuCm9a8DVA

 ������ȥ�������� ���ķ���˰�װ��

http://www.rabbitmq.com/download.html

�����Լ���ϵͳѡ�����ؼ���

**ע�⣡** **��Ҫ������Erlang�����ذ�װ����װ����Ȼ��װRabbitMQ����˵�ʱ�����ʾ�㱾��û��Erlang����**



**��װ�Ļ���** **�����Ͼ���Ĭ�ϵ�ѡ��ø�**

��ο�RabbitMq��װ����ˣ� ��ϵͳ-�������ҵ����¼��ɣ�

<img src="C:\Users\Administrator\Desktop\md\RabbitMq\p5.png" style="zoom: 80%;" />



�������� ֹͣ ���� �����



RabbitMQ��װ�ḽ��һ�������ߣ�����������ֱ�۵Ĳ鿴����RabbitMQ������״̬����ϸ���ݵȣ��е���Navicat ��ӦMysql�Ĺ�ϵ�� ֵ��һ����ǣ� �����ߺ�RabbitMQ�������� ϣ��ͬѧ�ǲ�Ҫ��ϡ�ˡ�

������������ʽ��

�����ǰ�װ�� RabbitMQ Server\rabbitmq_server-3.7.12\sbin Ŀ¼���� ִ��һ��cmd���

```
rabbitmq-plugins enable rabbitmq_management
```

ֱ�Ӹ������������ �� ��Ȼ ��ÿ�ζ�ҪȥĿ¼��ȥִ�е��鷳�Ļ��� ��������һ���������� ���������ǵĿ�ʼ�˵������ҵ������

<img src="C:\Users\Administrator\Desktop\md\RabbitMq\p6.png" style="zoom:67%;" />



��������������� ��΢��һ�»��н������ Ȼ����Դ������ ����

http://127.0.0.1:15672

���ʹ���ҳ�棺

![](C:\Users\Administrator\Desktop\md\RabbitMq\p7.png)

Ĭ���˺����붼�� guest ����

```
username ��guest
password��guest
```

��¼��ȥ֮��ῴ�����½��棨��Ϊ�Ҳ�С��װ��2��RabbitMq ���������ܿ������ظ��ˣ� �����Լ��ǲ����ظ���Ȼ�����Ǹո�˵�� �����ߺ�rabbitmq �������� ���Զ˿�Ҳ�Ͳ�һ����

<img src="C:\Users\Administrator\Desktop\md\RabbitMq\p8.png" style="zoom: 67%;" />



���ҳ���ڱʼ���������������ܱȽϸ��ӣ� �Ͳ�һһ�����ˣ� �����ｲ���ص㣬 �������ϻ�����һ��Ҫ��guest�û�����Ȼ guest����û�ֻ�ܱ������ܵ�½��ɾ�������¼�һ���û��� �������ʾһ���������

���� ���adminҳǩ�� �������ҵ�Add User

 ![](C:\Users\Administrator\Desktop\md\RabbitMq\p9.png)

Ȼ�������˺� ���� ȷ������ ���Tags��ʵ��һ���û�Ȩ�ޱ�ǩ�� �������Ľ��ܿ��Կ��ٷ����ܣ����Ա��Ǹ�С�ʺžͺ��ˣ�������ֱ�ӷ������Ľ��ܣ�

![](C:\Users\Administrator\Desktop\md\RabbitMq\p10.png)



![](C:\Users\Administrator\Desktop\md\RabbitMq\p11.png)

![](C:\Users\Administrator\Desktop\md\RabbitMq\p12.png)



��д��֮����AddUser �Ϳ������һ���û��ˣ� ������û�֮��Ҫ������û���Ӷ�Ӧ��Ȩ�ޣ�ע��Targ������Ȩ�ޣ�

����˵ �Ҹո������һ��jojo��ɫ !

![](C:\Users\Administrator\Desktop\md\RabbitMq\p13.png)

������jojo���Խ�ȥ�������Ȩ�� ���Ȩ�޿����� Virtual host ����� Ҳ�����ǽ���������� ������ϸ����ĳһ����д���� ������͸������һ��Virtual hostȨ��

![](C:\Users\Administrator\Desktop\md\RabbitMq\p14.png)



���� ���Ǹ����� testhost���Virtual host��Ȩ�� ����ƥ�䶼��* Ҳ��������Ȩ��

Ȼ����set������

��ô����ҳ�� ���Ǿͽ�������



## �ġ�RabbitMq���ٿ�ʼ

 ��Ϊ������������java����Ϊ�ͻ��ˣ� ������������maven������

```
<dependency>
   <groupId>com.rabbitmq</groupId>
   <artifactId>amqp-client</artifactId>
   <version>5.1.2</version>
 </dependency>
```

��ע����ǣ� �������������5.x��rabbitmq�ͻ��˰汾�� ��ô����jdk�İ汾�����8���ϣ���֮�� ����ͽ���ʹ��4.x�İ汾�������������jdk8 �����İ汾�������ۣ�

���� ���Ǳ�дһ�����ӵĹ����ࣺ

```
package com.test.util;

 import com.rabbitmq.client.Connection;
 import com.rabbitmq.client.ConnectionFactory;

 import java.util.ArrayList;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Map;

 public class ConnectionUtil {

   public static final String QUEUE_NAME = "testQueue";

   public static final String EXCHANGE_NAME = "exchange";


   public static Connection getConnection() throws Exception {
        //����һ�����ӹ���
        ConnectionFactory connectionFactory = new ConnectionFactory();
        //����rabbitmq ��������ڵ�ַ �������ڱ��ؾ��Ǳ���
        connectionFactory.setHost("127.0.0.1");
        //���ö˿ںţ������û����������ַ��
        connectionFactory.setPort(5672);
        connectionFactory.setUsername("jojo");
        connectionFactory.setPassword("jojo");
        connectionFactory.setVirtualHost("testhost");
        return connectionFactory.newConnection();
    }
 }


```

Ȼ�����Ǳ�дһ�������ߣ�producer������һ�������ߣ�consumer����

�����ߣ�

```
public class Consumer {

  	public static void sendByExchange(String message) throws Exception {

        Connection connection = ConnectionUtil.getConnection();
        Channel channel = connection.createChannel();
        //��������
        channel.queueDeclare(ConnectionUtil.QUEUE_NAME, true, false, false, null);
        // ����exchange
        channel.exchangeDeclare(ConnectionUtil.EXCHANGE_NAME, "fanout");
        //�������Ͷ��а�
        channel.queueBind(ConnectionUtil.QUEUE_NAME, ConnectionUtil.EXCHANGE_NAME, "");
        channel.basicPublish(ConnectionUtil.EXCHANGE_NAME, "", null, message.getBytes());
        System.out.println("���͵���ϢΪ:" + message);
        channel.close();
        connection.close();
    }

 }
```

�����ߣ�

```
public class Producer {

   public static void getMessage() throws Exception {
        Connection connection = ConnectionUtil.getConnection();
        Channel channel = connection.createChannel();
        //channel.queueDeclare(ConnectionUtil.QUEUE_NAME,true,false,false,null);
        DefaultConsumer deliverCallback = new DefaultConsumer(channel) {
            @Override
            public void handleDelivery(String consumerTag, Envelope envelope, AMQP.BasicProperties properties, byte[] body) throws IOException {
                System.out.println(new String(body, "UTF-8"));
            }
        };
        channel.basicConsume(ConnectionUtil.QUEUE_NAME, deliverCallback);
    }
 }


```

��� ������ʾ��fanout�����͵Ľ������� ���Բ���ҪroutingKey �Ϳ���·��ֻ��Ҫ�󶨼���

��������ͬѧҪ���ˣ� ���û�а󶨽�������ô���أ� û�а󶨽������Ļ��� ��Ϣ�ᷢ��rabbitmqĬ�ϵĽ��������� Ĭ�ϵĽ�������ʽ�İ������еĶ��У�Ĭ�ϵĽ�����������direct ·�ɽ����Ƕ��е����֣�

�����������ӵĻ����Ѿ�����һ�����������ˣ� ����������������Ŀ�����϶�����spring boot������û��spring bootҲ��spring �ɣ� ���Ժ�������ֱ�ӻ���spring boot�����⣨rabbitmq�����ԣ�ʵս�ȣ�



## �塢spring boot ����rabbitmq

spring boot�Ļ�����ô���߾Ͳ����ˣ� ��������spring boot -AMQP��������

```
<dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-amqp</artifactId>
 </dependency>
```



### ��������,����������������

#### ��������

���� �Һ�����һ�� ��Ҫ����������Ϣ���� ����ѡ��yml�ķ�ʽ Ҳ����ѡ��javaConfig�ķ�ʽ �������ַ�ʽ�Ҷ������� �����Լ�ѡ

yml�� ����ʲô��˼�ոս��ܹ��� ��������Լ��Ĳ������ȥ�ͺ���

```
spring:
  rabbitmq:
   host:
   port:
   username:
   password:
   virtual-host:
```

���� spring boot ������rabbitmq������صĶ������Զ�װ���ã�

javaConfig��

```
 @Bean
    public ConnectionFactory connectionFactory() {
        CachingConnectionFactory connectionFactory = new 		    CachingConnectionFactory("localhost", 5672);
        //������ֱ���ڹ��췽��������
        //    connectionFactory.setHost();
        //    connectionFactory.setPort();
        connectionFactory.setUsername("admin");
        connectionFactory.setPassword("admin");
        connectionFactory.setVirtualHost("testhost");
        //�Ƿ�����Ϣȷ�ϻ���
        //connectionFactory.setPublisherConfirms(true);
        return connectionFactory;
    }
```





����������֮�� ���ǾͿ��Կ�ʼ������Ϣ�ͽ�����Ϣ�ˣ���Ϊ��������ող���rabbitmq��ʱ�򴴽������кͽ������ȵ����ֶ����� ��Ȼ spring bootҲ���Դ�����

#### spring boot���������� ���� ���󶨣�

```
    @Bean
    public DirectExchange defaultExchange() {
        return new DirectExchange("directExchange");
    }

    @Bean
    public Queue queue() {
        //���� �Ƿ�־û�
        return new Queue("testQueue", true);
    }

    @Bean
    public Binding binding() {
        //��һ������ to: �󶨵��ĸ����������� with���󶨵�·�ɽ���routingKey��
        return BindingBuilder.bind(queue()).to(defaultExchange()).with("direct.key");
    }
```





#### ������Ϣ:

������Ϣ�Ƚϼ򵥣� spring �ṩ��һ��RabbitTemplate ������������ɷ�����Ϣ�Ĳ���

��������RabbitTemplate ��������һЩ���ã���������Щ�������Ǻ���ὲ���� ���ǿ�����config���� ������ΪBean new����������



```
 @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        //ע�� ���ConnectionFactory ��ʹ��javaconfig��ʽ�������ӵ�ʱ�����Ҫ����� �����yml���õ����ӵĻ��ǲ���Ҫ��
        RabbitTemplate template = new RabbitTemplate(connectionFactory);
        return template;
    }
```



```
 @Component
    public class TestSend {
        @Autowired
        RabbitTemplate rabbitTemplate;

        public void testSend() {
            //����Ϊʲô�������API ��������
            //�������ܣ� ���������֣�·�ɽ��� ��Ϣ����
            rabbitTemplate.convertAndSend("directExchange", "direct.key", "hello");
        }
    }
```

����ֻ��Ҫдһ���� Ȼ�󽻸�spring ���� ��������ע��RabbitTemplate �Ϳ���ֱ�ӵ���api��������Ϣ��



#### ������Ϣ��

�������½���һ����Ŀ������½�һ�� ��Ȼ ���½�Ҳû��ϵ�� ��������Ϣ��֮ǰ����������Ͳ��������� ���������һ������

```
@Component
 public class TestListener {

 @RabbitListener(queues = "testQueue")
   public void get(String message) throws Exception{
     System.out.println(message);
   }
 }
```



��������Ļ����������ܿ���Ч���� ����Ͳ���Ч��ͼ��

��ô����rabbitmq��һ�����ٿ�ʼ �Լ���spring boot���� ������ˣ� ���濪ʼ�ὲһЩrabbitmq��һЩ�߼����� �Լ�ԭ���

## ����RabbitMq����

### 6.1 ���ȷ����Ϣһ�����͵�Rabbitmq�ˣ�

 ���Ǹո������������� ����������� ��û����ģ� ���� ʵ�ʿ����� ��������Ҫ����һЩ������������� ���Ǵ���Ϣ�ķ��Ϳ�ʼ��

Ĭ������£����ǲ�֪�����ǵ���Ϣ������û�з��͵�rabbitmq���У� ��϶��ǲ���ȡ�ģ� ����������һ��������Ŀ�Ļ� �û����˶��� ����������Ϣ����� ��������Ϣû���͵�rabbitmq���� ���Ƕ����������ˣ���ʱ�� ��Ϊû����Ϣ ��治��ȥ���ٿ�棬 ���������Ƿǳ����صģ� ���� �������ͽ�һ�ֽ�������� ʧ�ܻص�



ʧ�ܻص��� ����˼�� ������Ϣ����ʧ�ܵ�ʱ��������������׼���õĻص����������Ұ�ʧ�ܵ���Ϣ ��ʧ��ԭ��� ���ع�����

���������

 **ע��** **ʹ��ʧ�ܻص�Ҳ��Ҫ�������ͷ�ȷ��ģʽ** **������ʽ������**

 ����RabbitmqTemplate:

```
 @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate template = new RabbitTemplate(connectionFactory);
        //����mandatoryģʽ������ʧ�ܻص���
        template.setMandatory(true);
        //ָ��ʧ�ܻص��ӿڵ�ʵ����
        template.setReturnCallback(new MyReturnCallback());
        return template;
    }
```



�ص��ӿڵ�ʵ���ࣺ

ʵ��RabbitTemplate.ReturnCallback�����returnedMessage�������� �������صĲ�����������

```
public class MyReturnCallback implements RabbitTemplate.ReturnCallback {

   @Override
   public void returnedMessage(Message message, int replyCode, String replyText, String exchange, String routingKey) {
     System.out.println(message);
     System.out.println(replyCode);
     System.out.println(replyText);
     System.out.println(exchange);
     System.out.println(routingKey);
   }
 }
```

����ģ��һ��ʧ�ܵķ��� �� ��ָ���Ľ��������ܰ���Ϣ·�ɵ�����ʱ��û��ָ��·�ɽ�����ָ����·�Ҽ�û�а󶨶�Ӧ�Ķ��� ����ѹ����û�а󶨶��ж���ʧ�ܣ� ��Ϣ�ͻᷢ��ʧ�� Ч��:

![](C:\Users\Administrator\Desktop\md\RabbitMq\p15.png)



�ֱ��ӡ���Ǵ���״̬�룬����ԭ�������ԭ���ǲ���·�ɣ� ���������� ��·�ɽ� �����и��������㷢�ͳ�ȥ����Ϣ ��Ϊ̫���˾�û��ͼ��.��



������Щͬѧ�뵽��һ����------����

û�������ȷ�ܽ��������⣬ ���� ǡ��rabbitmq�պ�Ҳ֧����� **���ǣ�** ����ǳ�Ӱ��rabbitmq������ �ж����أ� �������鵽������ ����Ȼ ֻ�������˽�� ͬѧ��Ҳ�����Լ�ȥ���Բ��Խ���� ����rabbitmq����Ļ� �����ܵ�Ӱ�쳬��100��֮�� Ҳ����˵ �����������һ����Ϣ��ʱ�� ���������ܴ���100��������������Ϊ�ɣ��� ��ô �����Ƿǳ�������ģ� ��Ϊ��Ϣ�м����������ʵ�ǳ��ؼ��ģ��ο�˫11�� ������������Ļ� ��Ȼ��ȷ����Ϣ100%Ͷ�ݳɹ� ���Ǵ���̫���ˣ�

��ô�������ﻹ��ʲô���������

rabbitmq��ʵ���ṩ��һ�ֽ�������� ��:**���ͷ�ȷ��ģʽ** ���ַ�ʽ �����ܵ�Ӱ��ǳ�С ����Ҳ��ȷ����Ϣ�Ƿ��ͳɹ�

���� ���ͷ�ȷ��ģʽһ��Ҳ���ʧ�ܻص�һ��ʹ�� ���� ����ȷ����Ϣ100%Ͷ����

���ͷ�ȷ�Ͽ���:

��ʵ�����������������ӵ�ʱ���Ѿ��ų����� ���������ӹ����Ǳ�ע�͵�һ�д��� ��


     connectionFactory.setPublisherConfirms(true);


�����yml���õĻ���

```
spring:
  rabbitmq:
   publisher-confirms: true
```



��ʧ�ܻص�һ�� ʵ��һ���ӿ�:

```
public class MyConfirmCallback implements RabbitTemplate.ConfirmCallback{

   @Override
   public void confirm(CorrelationData correlationData, boolean ack, String cause) {
     System.out.println(correlationData);
     System.out.println(ack);
     System.out.println(cause);
   }
 }
```



��RabbitmqTemplate ����һ��

```
template.setConfirmCallback(new MyConfirmCallback());
```



�������ǿ����ڷ�����Ϣ��ʱ�򸽴�һ��CorrelationData���� ��������������һ��id�����������ҵ��id ������ж�Ӧ�Ĳ���

```
CorrelationData correlationData = new CorrelationData(UUID.randomUUID().toString());
 rabbitTemplate.convertAndSend("directExchange", "direct.key123123", "hello",correlationData);
```

Ч����

 ![](C:\Users\Administrator\Desktop\md\RabbitMq\p16.png)

���������Ǵ�����Ǹ�ҵ��id �Լ�ack���Ƿ��ͳɹ��� �Լ�ԭ�� ���ػ���

���� Ҫע����� confirmģʽ�ķ��ͳɹ� ����˼�Ƿ��͵�RabbitMq��Broker���ɹ� �����Ƿ��͵����гɹ�

���Բ�������������˵���Ǿ� Ҫ��ʧ�ܻص����ʹ�� ��������ȷ����ϢͶ�ݳɹ���

���������е��ƣ� �򵥵��ܽ�һ�¾��� confirm������ȷ�����ǵ���Ϣ�Ƿ�Ͷ�ݵ��� RabbitMq��Broker������ ��mandatory�������ǵ���Ϣ�������ʧ��ʱ�򲻻ᱻ�������������Լ����д���



��ô���� ����rabbitmq�ڷ�����Ϣʱ���ǿ�������һЩ���� ���������ǻὲ��rabbitmq�ڽ��գ����ѣ���Ϣʱ��һЩ����

### 6.2 ���������ȷ�����ѣ�

ΪʲôҪȷ�����ѣ� Ĭ������� ���������õ�rabbitmq����Ϣʱ �Ѿ��Զ�ȷ��������Ϣ�Ѿ������ˣ� ���׻�����rabbitmq�Ķ�����ͻ�ɾ��������Ϣ�ˣ� ���� ����ʵ�ʿ����� ������������������ ����˵ �õ�������Ϣ �����Ҵ����� ����˵ �������ԣ� �ֱ���˵ �ҵ�ǰ���ϵͳ�������ˣ� ��ʱ���ܴ��������Ϣ�� ���� �����Ϣ�Ѿ��������ѵ��� rabbitmq�Ķ�����Ҳɾ�����ˣ� ���Լ�����ִ����ˣ� ��ô �������Ϣ�ͱ������ˡ� ���������ʵ�ʿ������ǲ�����ģ� rabbitmq�ṩ�˽���������ķ����� Ҳ��������������˵��confirmģʽ ֻ�����Ǹոս����Ƿ��ͷ��� ��������������ѷ��ġ�



���� ��������������ߣ���ǿ��һ�� �����ｨ���������ߺ������߷�������Ŀ�������������Լ����������ģ� ��Ȼһ����ĿҲ���ԣ��Ҿ��÷ֿ��Ļ��������һ�㣩

 ����һ����Ϣȷ��Ϊ�ֶ�ȷ��:

��Ȼ ����Ҫ�����ǵ������߼���������һ�������õĻ��� ������Ҫ��ʵ��һ����������Container Ҳ���������� ��ô���ǵļ�������һ���������������ʵ������������� ����ָ��������� ��ô����ֻ��Ҫ�����Container�������� �������þͿ�����

���ȵ�����һ��������������������ָ����Ϣȷ��Ϊ�ֶ�ȷ��:



```
@Bean
    public SimpleRabbitListenerContainerFactory simpleRabbitListenerContainerFactory(ConnectionFactory connectionFactory) {
        SimpleRabbitListenerContainerFactory simpleRabbitListenerContainerFactory =
                new SimpleRabbitListenerContainerFactory();
        //���connectionFactory���������Լ����õ����ӹ���ֱ��ע�����
        simpleRabbitListenerContainerFactory.setConnectionFactory(connectionFactory);
        //���������Ϣȷ�Ϸ�ʽ���Զ�ȷ�ϱ�Ϊ�ֶ�ȷ��
        simpleRabbitListenerContainerFactory.setAcknowledgeMode(AcknowledgeMode.MANUAL);
        return simpleRabbitListenerContainerFactory;
    }
```



AcknowledgeMode��������� ����һ���򵥵�ö���� ������������

```
public enum AcknowledgeMode {
    NONE,
    MANUAL,
    AUTO;

    private AcknowledgeMode() {
    }

    public boolean isTransactionAllowed() {
        return this == AUTO || this == MANUAL;
    }

    public boolean isAutoAck() {
        return this == NONE;
    }

    public boolean isManual() {
        return this == MANUAL;
    }
}
```



3��״̬ ��ȷ�� �ֶ�ȷ�� �Զ�ȷ��

���Ǹո����õľ����м��Ǹ� �ֶ�ȷ��

��Ȼ�������ֶ�ȷ���� ��ô�����ڴ�����������Ϣ֮�� ��ʹ������Ϣȷ�ϣ�

```
@Component
    public class TestListener {

        //containerFactory:ָ�����Ǹո����õ�����
        @RabbitListener(queues = "testQueue", containerFactory = "simpleRabbitListenerContainerFactory")
        public void getMessage(Message message, Channel channel) throws Exception {
            System.out.println(new String(message.getBody(), "UTF-8"));
            System.out.println(message.getBody());
            //�������ǵ�����һ���µ���������µ��ɹ�����ô������Ϣ�Ϳ���ȷ�ϱ�������
            boolean f = placeAnOrder();
            if (f) {
                //����������Ϣ�ı�ʶ�� �����ʶ��rabbitmq��ά�� ����ֻ��Ҫ��message���ó����Ϳ���
                //�ڶ���boolean����ָ���ǲ������������ ʲô�������������Ǵ�����ὲ��
                channel.basicAck(message.getMessageProperties().getDeliveryTag(), false);
            } else {
                //��Ȼ ��������������ʧ���� ����Ҳ��Ҫ����rabbitmq ������������Ϣ����ʧ���� �����˻� Ҳ�������� Ҫע����� ����������Ϣ�ɹ���� һ��Ҫ֪ͨ ����ʧ���� �����֪ͨ�Ļ� rabbitmq�˻���ʾ������Ϣһֱ����δȷ��״̬����ô������Ϣ�ͻ�һֱ�ѻ���rabbitmq�� ������rabbitmq�Ͽ����� ��ô���ͻ��������Ϣ���·������� ���� һ��Ҫ�ǵ�֪ͨ��
                //ǰ�������� �����������һ���� ���һ������ ����������Ϣ�Ƿ��ص�ԭ���� ����������Ϣ���� ���ǲ��˻��ˡ�
                channel.basicNack(message.getMessageProperties().getDeliveryTag(), false, true);
                //��ʵ ���APIҲ����ȥ����rabbitmq������Ϣʧ���� ��basicNack��֮ͬ�� ���� ����������������Ϣ��� ֻ�ܴ�������Ϣ  ��ʵbasicNack��ΪbasicReject����չ����������
                //channel.basicReject(message.getMessageProperties().getDeliveryTag(),true);
            }
        }
    }
```



��������µ�Ч���� �ҾͲ���ʾ����ҿ��ˣ� �������ҿ�һ����������˻���Ϣ��Ч��:

���� �Ұ���Ϣȷ�ϵĴ���ע�͵�:

```
//      channel.basicAck(message.getMessageProperties().getDeliveryTag(),false);*
```

Ȼ����������߷���һ����Ϣ ������������ҳ�棺

![](C:\Users\Administrator\Desktop\md\RabbitMq\p18.png)

�����ܿ��� ��һ����Ϣ��rabbitmq���� ����״̬��ready

Ȼ������ʹ�������������ѵ��� ע�� �������ǹ���û�и���rabbitmq�������ѳɹ��� ������Ч��

���� ���ѵĽ����ӡ�Ͳ���ͼ�� ������������ҳ�棺

 ![](C:\Users\Administrator\Desktop\md\RabbitMq\p19.png)

�����������Ѷ��������´� �����ܿ��� ������Ϣ���ǻ���rabbitmq���� ֻ������״̬Ϊ unacked ����δȷ��

��������Ǹո�˵��������� �������ѳɹ���� һ��Ҫ֪ͨrabbitmq ��Ȼ�ͻ����� һֱ�ڻ���rabbitmq���� ֱ�����ӶϿ�Ϊֹ.



### 6.3 ��ϢԤȡ

������Ϣȷ�� ��������һ�¸ո���˵���������������

ʲô����»�������������������أ�

������ ��Ҫ�ȳ�һ��rabbitmq����Ϣ���Ż�����

rabbitmq Ĭ�� ������� ����ѯ�Ļ��ưɶ������е���Ϣ���͸����пͻ��� �������Ϣûȷ�ϵĻ� �������һ��Unacked�ı�ʶ��ͼ�Ѿ������ˣ�

��ô ���ֻ��ƻ���ʲô�����أ� ����Rabbitmq���� ������������ٵ�ʹ�Լ�����ڻ���Ϣ�����������Ӱ�죬 ���� ������������ϵͳ������ ���ֻ��ƻ�����ܶ����⣬ ����˵ ��һ��������2����ͬʱ�����ѣ��������Ǵ���������ͬ�� �Ҵ����򵥵ıȷ� ��100��������Ϣ��Ҫ�������ѣ� ������������A ��������B �� ������A����һ����Ϣ���ٶ��� 10ms ������B ����һ����Ϣ���ٶ���15ms �� ��Ȼ ����ֻ�Ǵ�ȷ��� ��ô rabbitmq ��Ĭ�ϸ�������A B һ��50����Ϣ���������� ���� ������A ��500ms �Ϳ������������е���Ϣ ���Ҵ��ڿ���״̬ �� ������B��Ҫ750ms ���������� ����������������ǵĻ� ��100����Ϣ�������ʱ��һ����750ms����Ϊ2����ͬʱ�����ѣ� ������� ��������A�������ʱ�� �ܰ�������е�����������Bһ������ʣ�µ���Ϣ�Ļ��� ��ô�⴦���ٶȾͻ��ǳ��ࡣ

 ������ӿ����е���� ����ͨ����������ʾһ��

����Rabbitmq����100����Ϣ ��2�������������� ����������һ�������������ѵ�ʱ������0.5�루ģ�⴦��ҵ����ӳ٣� ����һ���������������� ����������Ч����

�������Ǹ������߻�һ˲���������Ϣ��50����ȫ�������꣨��Ϊ���Ǽ���������ٶȷǳ��죩 ��ͼ�Ǽ����ӳٵ������ߣ�

![img](file:///C:\Users\ADMINI~1\AppData\Local\Temp\msohtmlclip1\01\clip_image039.gif)



�����ұʼ������㿴����Ч����������Լ����Ծͻᷢ�� ����һ�������ߺܿ�ʹ������Լ�����Ϣ�� ����һ�������߻��������Ĵ��� ��ʵ ��������Ӱ�������ǵ������ˡ�

��ʵ������ô�� ������������������أ�

�Ҹոս��͹��� ������ԭ��ĸ�������rabbitmq��Ϣ�ķ��Ż��Ƶ��µģ� ��ô������������һ�½������: **��ϢԤȡ**

ʲô����ϢԤȡ�� ��������ǰ��rabbitmqһ���԰�������Ϣ�����������е������ߣ��������ܲ��ܵ��ˣ� ������ ����������������֮ǰ �ȸ���rabbitmq **��һ�������Ѷ�������** ������������֮�����rabbitmqrabbitmq�ٸ��ҷ�������

�ڴ�����������֣�

��ʹ����ϢԤȡǰ Ҫע��һ��Ҫ����Ϊ�ֶ�ȷ����Ϣ�� ԭ��ο����滮�ص���Ǿ仰��

��Ϊ���Ǹո����ù��� ����Ͳ��������ˣ� ����֮������һ������Ԥȡ��Ϣ������ һ�� ����������Container���������ã�

```
@Bean
 public SimpleRabbitListenerContainerFactory simpleRabbitListenerContainerFactory(ConnectionFactory connectionFactory){
   SimpleRabbitListenerContainerFactory simpleRabbitListenerContainerFactory =
       new SimpleRabbitListenerContainerFactory();
   simpleRabbitListenerContainerFactory.setConnectionFactory(connectionFactory);
   //�ֶ�ȷ����Ϣ
   simpleRabbitListenerContainerFactory.setAcknowledgeMode(AcknowledgeMode.MANUAL);
   //������ϢԤȡ������
   simpleRabbitListenerContainerFactory.setPrefetchCount(1);
   return simpleRabbitListenerContainerFactory;
 }


```

��ô������֮����ʲôЧ���أ� ���Ǹո��Ǹ����� ����2�������� ��Ϊ���������߷�����Ϣ��ȷ��֮�� rabbitmq�Ż����������Ϣ���ͻ��� ���ҿͻ��˵���Ϣ�ۼ������ᳬ�����Ǹո�����Ԥȡ�������� ��������������ͬ�������ӵĻ� �ᷢ�� A������������99����Ϣ�� B�����߲�����1�� ����ΪB������������0.5���������{������Ϣȷ��} ����0.5��֮��A�����߾��Ѿ���������Ϣ��������� ��Ȼ �������������ٶȽ������������ܻ��в���,Ч����ž���A�����߻ᴦ�������Ϣ��

�������Ч������B������ֻ����һ����Ϣ A�����߾��������ˣ� Ч��ͼ�Ͳ����� ����ͬѧ�Ǿ����Լ�����һ�� ���߸ı�һ�²�������Ч����

�������Ԥȡ��������������أ� ���Ƿ��� �������Ϊ1 �ܼ�������ÿͻ��˵����ܣ����������˾Ϳ��ԸϽ�������һ�� ���ᵼ��æ�ĺ�æ �еĺ��У� ���ǣ� ����ÿ����һ����Ϣ ��Ҫ֪ͨһ��rabbitmq Ȼ����ȡ���µ���Ϣ�� ��������rabbitmq���������� �Ƿǳ�������� �����������Ҫ����ҵ���������

�Ҹ����Ҳ��ĵ�������Ȼ����Բ��ԣ� �����ֵ�Ĵ�С�����ܳ����� ���������ޣ������ݿɿ��ԣ��Լ����Ǹո���˵�Ŀͻ��˵������ʳɷ��� �������ͼ��



 <img src="C:\Users\Administrator\Desktop\md\RabbitMq\p21.png" style="zoom:67%;" />



��ô����ȷ�ϣ� ���Ƕ�������Ԥȡ����Ϣ������ͳһ��ȷ�ϡ�



### 6.4 ���Ž�����

��������һ�δ���:

```
channel.basicNack(message.getMessageProperties().getDeliveryTag(),false,true);
```

����������͹� �����������Ϣ����ʧ�ܵ�ȷ�� Ȼ��������������н��͹�����Ϣ�Ƿ񷵻ص�ԭ���У� ��ô�������ˣ���� û�з��ظ�ԭ���� ��ô������Ϣ�ͱ������ˣ�

rabbitmq���ǵ�����������ṩ�˽�������� **���Ž�����**(��Щ�˿��ܽ�������������,������������)

���Ž�������ʲô���أ� �ڴ������е�ʱ�� ���Ը�������и���һ���������� ��ô����������ϵ���Ϣ�ͻᱻ���·��������Ľ�������Ȼ�����������������·��������Ϣ

 ������������ �������£�

```
 @Bean
    public Queue queue() {
        Map<String,Object> map = new HashMap<>();
        //������Ϣ�Ĺ���ʱ�� ��λ����
        map.put("x-message-ttl",10000);
        //���ø��������Ž�����
        map.put("x-dead-letter-exchange","exchange.dlx");
        //ָ���ض����·�ɽ� ��Ϣ����֮����Ծ����費��Ҫ��������·�ɽ� �����Ҫ ��������ָ��
        map.put("x-dead-letter-routing-key","dead.order");
        return new Queue("testQueue", true,false,false,map);
    }
```

�����������һ��Ч����



 ![](C:\Users\Administrator\Desktop\md\RabbitMq\p22.png)



��ʵ���Ǹոշ��� ��ν���Ž������� ֻ�Ƕ�Ӧ�Ķ��������˶�Ӧ�Ľ����������Ž������� ���ڽ����������� ������һ����ͨ�Ľ����� ��

������г�rabbitmq�ĳ������ã�

�������ã�

| ������                    | ��������                           |
| ------------------------- | ---------------------------------- |
| x-dead-letter-exchange    | ���Ž�����                         |
| x-dead-letter-routing-key | ������Ϣ�ض���·�ɼ�               |
| x-expires                 | ������ָ����������ɾ��           |
| x-ha-policy               | ����HA����                         |
| x-ha-nodes                | HA���еķֲ��ڵ�                   |
| x-max-length              | ���е������Ϣ��                   |
| x-message-ttl             | ����Ϊ��λ����Ϣ����ʱ�䣬���м��� |
| x-max-priority            | �������ֵΪ255�Ķ�������������  |

��Ϣ���ã�

| ������           | ��������                                               |
| ---------------- | ------------------------------------------------------ |
| content-type     | ��Ϣ���MIME���ͣ���application/json                   |
| content-encoding | ��Ϣ�ı�������                                         |
| message-id       | ��Ϣ��Ψһ�Ա�ʶ����Ӧ�ý�������                       |
| correlation-id   | һ������������Ϣ��message-id����������Ϣ����Ӧ         |
| timestamp        | ��Ϣ�Ĵ���ʱ�̣����Σ���ȷ����                         |
| expiration       | ��Ϣ�Ĺ���ʱ�̣� �ַ��������ǳ��ָ�ʽΪ���ͣ���ȷ����  |
| delivery-mode    | ��Ϣ�ĳ־û����ͣ�1Ϊ�ǳ־û���2Ϊ�־û�������Ӱ��޴� |
| app-id           | Ӧ�ó�������ͺͰ汾��                                 |
| user-id          | ��ʶ�ѵ�¼�û�������ʹ��                               |
| type             | ��Ϣ�������ƣ���ȫ��Ӧ�þ������ʹ�ø��ֶ�             |
| reply-to         | �����ظ���Ϣ��˽����Ӧ����                             |
| headers          | ��/ֵ�Ա��û��Զ�������ļ���ֵ                      |
| priority         | ָ����������Ϣ�����ȼ�                                 |





## �ߡ�Rabbitmq linux��װ&��Ⱥ�߿���

### 7.1 rabbitmq linux�°�װ

���￼�ǵ�������ͬѧû�˽��linux ���߲�̫��Ϥlinux �������ص�ַ֮��Ķ���������ֱ�����ֳɵģ� Ҳ����˵ ֻҪ�����ҵĲ�������ȥ�����϶�û����.

�ڰ�װ(���Ⱥ)֮ǰ ȷ��������  **1:����ǽ�ص�2:������**

�رշ���ǽ

```
systemctl stop firewalld.service
```

 ��ֹ��������

```
systemctl disable firewalld.service
```

���� ���ǰ�װerlang

* ����erlang

```
wget http://www.rabbitmq.com/releases/erlang/erlang-18.2-1.el6.x8664.rpm
```

* ��װerlang

```
  rpm -ihv http://www.rabbitmq.com/releases/erlang/erlang-18.2-1.el6.x86*64.rpm
```



��װ��erlang֮�� ��ʼrabbitmq ����������һ�� ��װerlang ��װrabbitmq

װRabbitmq֮ǰ ��װһ����Կ :

```
rpm --import https://dl.bintray.com/rabbitmq/Keys/rabbitmq-release-signing-key.asc
```

װ�ù�Կ֮�� ����Rabbitmq:

```
wget http://www.rabbitmq.com/releases/rabbitmq-server/v3.6.6/rabbitmq-server-3.6.6-1.el7.noarch.rpm
```

��װ:

```
rpm -ihv rabbitmq-server-3.6.6-1.el7.noarch.rpm
```

��װ��;���ܻ���ʾ����Ҫһ����socat�Ĳ��

�����ʾ�� ���Ȱ�װsocat ��װrabbitmq

��װsocat:

```
yum install socat
```

���� ��װ����Rabbitmq�� ����ִ��������������Rabbitmq:

```
service rabbitmq-server start
```



��windows������һ�� rabbitmq����linuxҲ�ṩ�����Ĺ�����

��װrabbitmq������:

```
rabbitmq-plugins enable rabbitmq_management
```

��װ�������֮�� �����װ��������Ļ� ������ ���Ժ�windowsһ�� ���� һ�� localhost:15672 ���Կ���һ����Ϥ��ҳ�棺

<img src="C:\Users\Administrator\Desktop\md\RabbitMq\p23.png" style="zoom:80%;" />

��Ȼ ��������һ�� ������������linux�Ļ� ��������������һ��Ҳ��û�����

 ��ô ��װ ���Ǿͽ����� ��������������Ⱥ�����Ĵ �Լ�һЩ����

### 7.2 rabbitmq��Ⱥ�������

rabbbitmq��������erlang���Կ����� ������֧�ֲַ�ʽ

rabbitmq �ļ�Ⱥ������ģʽ һ����Ĭ��ģʽ һ���Ǿ���ģʽ

��Ȼ ��ν�ľ���ģʽ�ǻ���Ĭ��ģʽ����һ������������

��rabbitmq��Ⱥ���� ���еĽڵ㣨һ��rabbitmq�������� �ᱻ��Ϊ���� һ���Ǵ��̽ڵ� һ�����ڴ�ڵ�

���̽ڵ��Ѽ�Ⱥ��������Ϣ(���罻����,���е���Ϣ)�־û������̵��У����ڴ�ڵ�ֻ�Ὣ��Щ��Ϣ���浽�ڴ浱�� ������ ����һ���û�ˡ�

Ϊ�˿����Կ��� rabbitmq�ٷ�ǿ����Ⱥ����������Ҫ��һ�����̽ڵ㣬 ����Ϊ�˸߿��õĻ��� ��������Ҫ��2�����̽ڵ㣬 ��Ϊ���ֻ��һ�����̽ڵ� ���պ���Ψһ�Ĵ��̽ڵ�崻��˵Ļ��� ��Ⱥ��Ȼ���ǿ��������� ���ǲ��ܶԼ�Ⱥ�����κε��޸Ĳ��������� ������ӣ���������ӣ�����/�Ƴ� �µĽڵ�ȣ�



��������rabbitmqʵ�ּ�Ⱥ�� ����������Ҫ��һ��ϵͳ��hostname (��Ϊrabbitmq��Ⱥ�ڵ������Ƕ�ȡhostname��)

���� ����ģ��3���ڵ� :

rabbitmq1

rabbitmq2

rabbitmq3

linux�޸�hostname����:

```
hostnamectl set-hostname [name]
```

**�޸ĺ�����һ��** ��rabbitmq���¶�ȡ�ڵ�����

Ȼ�� ������Ҫ��ÿ���ڵ�ͨ��hostname��pingͨ��**�ǵùرշ���ǽ**�� ���� ���ǿ����޸��޸�һ��hosts�ļ�

�رշ���ǽ

```
systemctl stop firewalld.service
```

 ��ֹ��������

```
systemctl disable firewalld.service
```

������,������Ҫ�������ڵ��.erlang.cookie�ļ����ݱ���һ��(�ļ�·��/var/lib/rabbitmq/.erlang.cookie)

��Ϊ���ǲ���������ķ�ʽ��ģ�⼯Ⱥ������ �����������һ���ǿ�¡��������Ļ� ͬ��.erlang.cookie�ļ���������ڿ�¡��ʱ����Ѿ�����ˡ�

������Щ�������֮�� ���ǾͿ��Կ�ʼ��������Ⱥ ��

��������rabbitmq2 ���� rabbitmq1��������Ϊһ����Ⱥ

ִ������( ram:ʹrabbitmq2��Ϊһ���ڴ�ڵ� Ĭ��Ϊ:disk ���̽ڵ�)��

```
rabbitmqctl stopapp rabbitmqctl joincluster rabbit@rabbitmq1 --ram rabbitmqctl start_app
```

�ڹ�����ʱ�� ������Ҫ��ͣ��rabbitmqctl������ܹ��� �ȹ������֮��������

���ǰ�rabbitmq2�����֮����rabbitmq3�ڵ���Ҳִ��ͬ���Ĵ��� ʹ��Ҳ�����ȥ ��Ȼ ����Ҳ������rabbitmq3Ҳ��Ϊһ�����̽ڵ�

��ִ��������Ժ�����������Ч��:

 ![](C:\Users\Administrator\Desktop\md\RabbitMq\p26.png)



������ĸ��ڵ�򿪹���ҳ�涼�ܿ�����Ⱥ�������ڵ����Ϣ;

�йؼ�Ⱥ����������:

```
 rabbitmq-server -detached ����RabbitMQ�ڵ�
 rabbitmqctl startapp ����RabbitMQӦ�ã������ǽڵ�
 rabbitmqctl stopapp ֹͣ
 rabbitmqctl status �鿴״̬
 rabbitmqctl adduser mq 123456 rabbitmqctl setusertags mq administrator �����˻�
 rabbitmq-plugins enable rabbitmqmanagement ����RabbitMQManagement
 rabbitmqctl clusterstatus ��Ⱥ״̬
 rabbitmqctl forgetclusternode rabbit@[nodeName] �ڵ�ժ��
 rabbitmqctl reset application ����
```



��ͨģʽ��rabbitmq��Ⱥ��ú� ������˵һ�¾���ģʽ

����ͨģʽ�µ�rabbitmq��Ⱥ ��������нڵ�Ľ�������Ϣ �Ͷ��е�Ԫ����(�������ݷ�Ϊ���� һ��Ϊ�����������Ϣ�� ����һ���Ƕ��б������Ϣ ������е�������������е����ƣ��ȵ�������Ϣ�� ���߳�֮ΪԪ����) ���и��� ȷ�����нڵ㶼��һ�ݡ�

������ģʽ�����ǰ����еĶ���������ȫͬ������Ȼ �����ܿ϶�����һ��Ӱ�죩 �������ݿɿ���Ҫ���ʱ ����ʹ�þ���ģʽ

ʵ�־���ģʽҲ�ǳ��� ��2�ַ�ʽ һ����ֱ���ڹ���̨���ƣ� ����һ�������������е�ʱ�����

�������е�ʱ����Լ��뾵����в��� ���Ϸ��Ĳ����б����н��� ��������һ�¹���̨����

�����������������ͣ�

```
rabbitmqctl set_policy [-p Vhost] Name Pattern Definition [Priority]
```

```
-p Vhost�� ��ѡ���������ָ��vhost�µ�queue��������
Name: policy������
Pattern: queue��ƥ��ģʽ(������ʽ)
Definition�������壬������������ha-mode, ha-params, ha-sync-mode
     ha-mode:ָ��������е�ģʽ����ЧֵΪ all/exactly/nodes
        all����ʾ�ڼ�Ⱥ�����еĽڵ��Ͻ��о���
        exactly����ʾ��ָ�������Ľڵ��Ͻ��о��񣬽ڵ�ĸ�����ha-paramsָ��
        nodes����ʾ��ָ���Ľڵ��Ͻ��о��񣬽ڵ�����ͨ��ha-paramsָ��
     ha-params��ha-modeģʽ��Ҫ�õ��Ĳ���
     ha-sync-mode�����ж�������Ϣ��ͬ����ʽ����ЧֵΪautomatic��manual
```

����ٸ����� ����������������ֿ�ͷΪ policy�Ķ��н��о��� ��������Ϊ1��ô��������:

```
rabbitmqctl setpolicy hapolicy "^policy_" '{"ha-mode":"exactly","ha-params":1,"ha-sync-mode":"automatic"}'
```



 