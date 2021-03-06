## AES+RSA结合应用Java Spring-Boot示例
### 介绍
#### 对称加密
对称加密是指加密和解密使用同一个密钥的加密方式。发送方使用密钥将明文数据加密成密文，然后发送出去，接收方收到密文后，使用同一个密钥将密文解密成明文读取。<br>
对称加密具有加密计算量小、速度块的优点，适合对大量数据进行加密的场景。<br>
由于对称加密的加密和解密使用的是同一个密钥，因此密钥的传输问题、保存问题是对称加密的两大缺点。
#### 非对称加密
非对称加密是指需要用一对密钥，即公钥和私钥，来完成加解密的方式。如果用公钥加密，则只能用对应的私钥才能解密；而如果用私钥加密，则只能用对应的公钥才能解密。<br>
非对称加密解决了对称加密的两大不足：密钥传输问题和密钥管理问题。<br>
非对称加密的缺点在于加密计算量大、速度慢，因此适合对少量数据进行加密的场景。
#### 实际应用
由于两种加密方式各有优劣，一般实际应用时扬长避短，使用对称加密法加密报文，使用非对称加密法加密对称加密的密钥。<br>
AES是常用的对称加密算法，RSA是常用的非对称加密算法。

### 加解密流程
#### 客户端到服务端
1. 服务端生成RSA公钥(publicKey)、私钥(privateKey).
2. 客户端生成AES密钥(aesKey)，使用AES将报文加密成密文(data).
3. 客户端获取publicKey，使用RSA对aesKey加密(encryptKey).
4. 客户端将data和encryptKey作为参数传给服务端.
#### 服务端返回结果给客户端
1. 因为从客户端传来的aesKey是安全的，所以服务端直接用aesKey加密返回报文，将密文返回即可.

### 应用方案
因为要对接口入参、出参进行加解密，所以要对接口进行拦截。<br>
在Spring-Boot框架下，常用的拦截方法有AOP、过滤器等。<br>
此项目包含：<br>
- [x] 注解+AOP<br>
- [ ] 过滤器
#### 注解+AOP
首先自定义注解@Decrypt、@Encrypt，分别对应对请求入参解密、对返回结果加密操作。<br>
然后AOP扫描指定包下的Controller，拦截带自定义标签的Post请求，进行入参解密、出参加密操作。<br>
详见代码 ./src/main/java/cn/example/web/demo/security/SecurityAspect.java

#### 使用过滤器
*待完善*

### 参考文档
1. [网络传输数据加解密方案选择（RSA+AES）](https://blog.csdn.net/yuzhiqiang_1993/article/details/88641265)
2. [对称加密及AES加密算法](https://www.jianshu.com/p/3840b344b27c)
3. [非对称加密及RSA加密算法](https://www.jianshu.com/p/9785bd492a6e)
