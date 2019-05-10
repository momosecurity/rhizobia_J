# 简介：
```
java安全sdk旨在封装针对java代码的安全防护的方法，用于协助java开发人员解决常见的java代码相关的安全漏洞， 提高java开发人员的开发效率、保障业务安全的同时，又不影响业务的正常功能、最小化影响性能。
目前第一版包括了SQL注入防护、xss防护、url重定向防护、SSRF防护、CSRF防护、readObject反序列化漏洞防护、xxe防护、AES加解密、RSA加解密
```
#### 如有疑问，请联系。

### 项目结构
```
├── README.md
├── pom.xml
└── src
    ├── LICENSE
    ├── main
    │   ├── java
    │   │   └── com
    │   │       └── immomo
    │   │           └── rhizobia
    │   │               └── rhizobia_J
    │   │                   ├── base
    │   │                   │   ├── SqliSanitiser.java
    │   │                   │   └── WhiteChecker.java
    │   │                   ├── crypto
    │   │                   │   ├── AESUtils.java
    │   │                   │   └── RSAUtils.java
    │   │                   ├── csrf
    │   │                   │   └── CSRFTokenUtils.java
    │   │                   ├── deserialization
    │   │                   │   └── SecureObjectInputStream.java
    │   │                   ├── extra
    │   │                   │   ├── LICENSE
    │   │                   │   ├── LICENSE-CONTENT
    │   │                   │   ├── LICENSE-README
    │   │                   │   ├── codecs
    │   │                   │   │   ├── AbstractCharacterCodec.java
    │   │                   │   │   ├── AbstractCodec.java
    │   │                   │   │   ├── AbstractIntegerCodec.java
    │   │                   │   │   ├── AbstractPushbackSequence.java
    │   │                   │   │   ├── Codec.java
    │   │                   │   │   ├── DB2Codec.java
    │   │                   │   │   ├── HTMLEntityCodec.java
    │   │                   │   │   ├── HashTrie.java
    │   │                   │   │   ├── JavaScriptCodec.java
    │   │                   │   │   ├── MySQLCodec.java
    │   │                   │   │   ├── OracleCodec.java
    │   │                   │   │   ├── PushBackSequenceImpl.java
    │   │                   │   │   ├── PushbackSequence.java
    │   │                   │   │   ├── PushbackString.java
    │   │                   │   │   └── Trie.java
    │   │                   │   └── commons
    │   │                   │       ├── CollectionsUtil.java
    │   │                   │       ├── EncoderConstants.java
    │   │                   │       ├── NullSafe.java
    │   │                   │       ├── RandomCreater.java
    │   │                   │       └── StringUtilities.java
    │   │                   ├── sqli
    │   │                   │   ├── DB2Sanitiser.java
    │   │                   │   ├── MysqlSanitiser.java
    │   │                   │   └── OracleSanitiser.java
    │   │                   ├── ssrf
    │   │                   │   └── SSRFWhiteChecker.java
    │   │                   ├── urlredirection
    │   │                   │   └── UrlRedirectionWhiteChecher.java
    │   │                   ├── xss
    │   │                   │   └── XssSanitiser.java
    │   │                   └── xxe
    │   │                       └── XmlUtils.java
    │   └── resources
    │       └── log4j.properties
    └── test
        └── java
            └── com
                └── immomo
                    └── rhizobia
                        └── rhizobia_J
                            ├── AESUtilsTest.java
                            ├── CSRFTokenUtilsTest.java
                            ├── DB2SanitiserTest.java
                            ├── MysqlSanitiserTest.java
                            ├── OracleSanitiserTest.java
                            ├── SSRFWhiteCheckerTest.java
                            ├── SafeClass.java
                            ├── SecureObjectInputStreamTest.java
                            ├── TestBean.java
                            ├── UnsafeClass.java
                            ├── UrlRedirectionWhiteChecherTest.java
                            ├── XmlUtilsTest.java
                            └── XssEncoderTest.java
```

## 目录

* [1、引用java security library](#importjsl)
* [2、SQL注入防护](#sqlInjection)
* [3、xss防护](#xss)
* [4、url重定向防护](#urlredirection)
* [5、SSRF防护](#ssrf)
* [6、CSRF防护](#csrf)
* [7、readObject反序列化漏洞防护](#readobjectdeserialization)
* [8、xxe防护](#xxe)
* [9、AES加解密](#aes)
* [10、RSA加解密](#rsa)

<h3 id="importjsl">1、引用java security library</h3>

#### 环境需求
* Java 8
* Maven 3

#### a、编译jar包：
```
    mvn -Dmaven.test.skip=true clean install
```

#### b、引入java security library:
在target目录中找到target/common-utils-1.0-SNAPSHOT.jar，导入工程中

> 需要在自己的maven工程pom.xml中加入如下依赖
```
    <dependency>
        <groupId>log4j</groupId>
        <artifactId>log4j</artifactId>
        <version>1.2.17</version>
    </dependency>
    <dependency>
        <groupId>commons-codec</groupId>
        <artifactId>commons-codec</artifactId>
        <version>1.11</version>
    </dependency>
```

<h3 id="sqlInjection">2、SQL注入防护</h3>

#### a、确认是连接的是哪种数据库，选择对应的数据库编码，目前支持数据库包括：MySQL Oracle DB2:
```Java
    import com.immomo.rhizobia.rhizobia_J.sqli.MysqlSanitiser;
    //import com.immomo.rhizobia.rhizobia_J.sqli.OracleSanitiser;
    //import com.immomo.rhizobia.rhizobia_J.sqli.DB2Sanitiser;
    
    MysqlSanitiser sqlTool = MysqlSanitiser.getInstance();
```

#### b、对sql语句中拼接的参数进行转义:
```Java
    String id = "1' or '1'='1' #";
    String idEncode = sqlTool.mysqlSanitise(id);
    String query = "SELECT NAME FROM users WHERE id = '" + idEncode + "'";
```
__使用order by、group by等需要转换列名时，需使用带boolean参数__
```Java
    //保证列名中的下划线不被转义
    String columnName = "user_name";
    String columnNameEncode = sqlTool.mysqlSanitise(columnName, true);
    query = "SELECT NAME FROM users order by " + columnNameEncode ;
```

#### c、转义前后对比:
```Java
    转义前：SELECT NAME FROM users WHERE id = '1' or '1'='1' #'
    转义后：SELECT NAME FROM users WHERE id = '1\' or \'1\'\=\'1\' \#'
```

#### d、表名列名转义前后对比:
```Java
    转义前：SELECT NAME FROM users order by user_name
    转义后：SELECT NAME FROM users order by user_name
    转义前：SELECT NAME FROM users order by user-name
    转义后：SELECT NAME FROM users order by user\-name
```

<h3 id="xss">3、xss防护</h3>

#### a、调用XssSanitiser单例:
```Java
    import com.immomo.rhizobia.rhizobia_J.xss.XssSanitiser;
    
    XssSanitiser xssFilter = XssSanitiser.getInstance();
```

#### b、如果输出到html body:
```Java
    String ret = xssFilter.encodeForHTML(oriString);
```
过滤前后对比:
```Java
    过滤前：<script> alert('xss') </script>
    过滤后：&lt;script&gt;alert&#x28;&#x27;xss&#x27;&#x29;&lt;&#x2f;script&gt;
```

#### c、如果输出到html标签的属性(多了对空字符的过滤):
```Java
    String ret = xssFilter.encodeForHTMLAttribute(oriString);
```
过滤前后对比:
```Java
    过滤前：<script> alert('xss') </script>
    过滤后：&lt;script&gt;&#x20;alert&#x28;&#x27;xss&#x27;&#x29;&#x20;&lt;&#x2f;script&gt;
```

#### d、如果输出到JavaScript代码块中:
```Java
    String ret = xssFilter.encodeForJavaScript(oriString);
```
过滤前后对比:
```Java
    过滤前：alert('xss');
    过滤后：alert\x28\x27xss\x27\x29\x3B
```

<h3 id="urlredirection">4、url重定向防护</h3>

#### a、调用UrlRedirectionWhiteChecher单例:
```Java
    import com.immomo.rhizobia.rhizobia_J.urlredirection.UrlRedirectionWhiteChecher;
    
    UrlRedirectionWhiteChecher urlChecker = UrlRedirectionWhiteChecher.getInstance();
```

#### b、自定义白名单:
```Java
    List<String> whitelist = new ArrayList<String>();
    String white1=".trust1.com";
    String white2=".trust2.com";
    
    //setWhiteList会先清空原有白名单列表
    //在原有基础上新增白名单，使用addWhiteList(whitelist)
    urlChecker.setWhiteList(whitelist);

```

#### c、校验url:
```Java
    try{
        boolean isWhite = urlChecker.verifyURL(url.trim());
    } catch (Exception e) {
        ...
    }
```

<h3 id="ssrf">5、SSRF防护</h3>

#### a、调用SSRFWhiteChecker单例，与前面url重定向类似:
```Java
    import com.immomo.rhizobia.rhizobia_J.ssrf.SSRFWhiteChecker;
    
    SSRFWhiteChecker ssrfChecker = SSRFWhiteChecker.getInstance();
```

#### b、自定义白名单:
```Java
    List<String> whitelist = new ArrayList<String>();
    String white1=".trust1.com";
    String white2=".trust2.com";
    
    //setWhiteList会先清空原有白名单列表
    //在原有基础上新增白名单，使用addWhiteList(whitelist)
    ssrfChecker.setWhiteList(whitelist);

```

#### c、校验url:
```Java
    try{
        boolean isWhite = ssrfChecker.verifyURL(url.trim());
    } catch (Exception e) {
        ...
    }
```

<h3 id="csrf">6、CSRF防护</h3>

#### a、随机算出csrf token，并且每次生成随机值都不一样（实测结果连续生成1000亿次无重复）:
```Java
    import com.immomo.rhizobia.rhizobia_J.csrf.CSRFTokenUtils;

    CSRFTokenUtils csrfInstance = CSRFTokenUtils.getInstance();
    String token = csrfInstance.resetCsrfToken(32);
```
#### b、后端保存生成的token，以待校验（可以采用数据库、分布存储等任意存储手段）

#### c、前端页面加上hidden字段
**form中加入csrf token的hidden字段：**
```Jsp
    <input name="${(_csrf.parameterName)!}" value="${(_csrf.token)!}" type="hidden">
```

**ajax中加入csrf头**
```Jsp
    xhr.setRequestHeader("${_csrf.headerName}", "${_csrf.token}");
```

#### d、当前端向后端发送请求时，请求header中携带token，后端收到后与之前存储的token进行校验


<h3 id="readobjectdeserialization">7、readObject反序列化漏洞防护</h3>

#### a、选择适当的构造函数初始化，自定义白名单:

**使用SecureObjectInputStream中适当的构造函数，增加自定义的白名单**
```Java
    import com.immomo.rhizobia.rhizobia_J.deserialization.SecureObjectInputStream;

    SecureObjectInputStream(InputStream in, String[] classlist)
    SecureObjectInputStream(InputStream in, List<String> classlist)
```

#### b、使用安全的类SecureObjectInputStream，恢复非白名单中类的对象时会抛出异常:

```Java
    List<String> classlist = new ArrayList<String>();
    classlist.add(SafeClass.class.toString());
    
    try{   
        //考虑如果白名单为空时会影响正常判断逻辑，所以此处会抛出异常
        SecureObjectInputStream ois = new SecureObjectInputStream(fis, classlist);
        
        //使用安全的SecureObjectInputStream恢复对象时会抛出exception
        UnsafeClass objectFromDisk = (UnsafeClass)ois.readObject();
    } catch (Exception e) {
        ...
    }
```

<h3 id="xxe">8、xxe防护</h3>

### 8.1、解析xml内容为Document

#### a、初始化时注意xml编码格式:
```Java
    import com.immomo.rhizobia.rhizobia_J.xxe.XmlUtils;
    //如果xml格式包含外部实体，会抛异常
    try{
        Document doc =  XmlUtils.getInstance().newDocument(xmlFile, "utf-8");
    } catch (Exception e) {
        ...
    }
```

#### b、使用生成的Document对象:
```Java
    Node notifyNode = doc.getFirstChild();
    NodeList list = notifyNode.getChildNodes();
    for (int i = 0, length = list.getLength(); i < length; i++) {
        Node n = list.item(i);
        String nodeName = n.getNodeName();
        String nodeContent = n.getTextContent();
        System.out.println(nodeName.toString() + "    " + nodeContent.toString());
    }
```

### 8.2、解析xml内容为Bean 

#### a、自定义TestBean，然后调用converyToJavaBean解析:
```Java
    import com.immomo.rhizobia.rhizobia_J.xxe.XmlUtils;

    //如果xml格式包含外部实体，会抛异常
    XmlUtils xmlParser =  XmlUtils.getInstance();
    try {
        TestBean testbean = (TestBean)xmlParser.converyToJavaBean(xmlFile, TestBean.class);
    } catch (Exception e) {
        ...
    }
```

#### b、使用生成的bean对象:
```Java
    testbean.getTo()
    testbean.getFrom()
    testbean.getHeading()
    testbean.getBody()
```

<h3 id="aes">9、AES加解密</h3>
#### a、调用AESUtils:

```Java
    import com.immomo.rhizobia.rhizobia_J.crypto.AESUtils;
    
    AESUtils aesInstance = AESUtils.getInstance(String aesKey, String secretKey, String aesMode);
    /**
    参数说明：
        aesKey:     用于生成密钥的原始字符串，推荐使用session/id，具有唯一性
        secretKey:  加解密双方约定的secret
        aesMode:    值为null时，默认采用"AES/CBC/PKCS5Padding"
    */
    AESUtils aesInstance = AESUtils.getInstance("843739488","TcmEqGzSpH5S2VgoUix7HJ9cwqCofoUD",null);
```

#### b、加密

```Java
    String orginText = "10000";
    
    byte[] ciphertext = aesInstance.Encrypt(orginText);
    //由于返回是byte流，所以如果需要base64编码或转换成Hex，需另做处理
    String encryptRet = new BASE64Encoder().encode(ciphertext);
```

#### c、解密

```Java
    //同样，如果加密内容用base64编码或转换成Hex，解密时需另做处理
    byte[] encrypted = new BASE64Decoder().decodeBuffer(encryptRet);
    String DeString = aesInstance.Decrypt(encrypted);
```

<h3 id="rsa">10、RSA加解密</h3>
#### a、调用RSAUtils:

```Java
    import com.immomo.rhizobia.rhizobia_J.crypto.RSAUtils;
    
    RSAUtils rsaInstance = RSAUtils.getInstance(priKeyPath, pubKeyPath);
    /**
    参数说明：目前证书支持 PEM 格式
        priKeyPath:  openssl生成的私钥地址
        pubKeyPath:  openssl生成的公钥地址
    */
    String priKeyPath = "/tmp/pri.key";
    String pubKeyPath = "/tmp/pub.key";
    RSAUtils rsaInstance = RSAUtils.getInstance(priKeyPath, pubKeyPath);
```

#### b、加密

```Java
    String plaintext = "123";

    byte[] ciphertext = rsaInstance.encrypt(plaintext);
    //与aes一样返回是byte流，所以如果需要base64编码或转换成Hex，需另做处理
    String encryptRet = new BASE64Encoder().encode(ciphertext);
```

#### c、解密

```Java
    //同样，如果加密内容用base64编码或转换成Hex，解密时需另做处理
    byte[] encrypted = new BASE64Decoder().decodeBuffer(encryptRet);
    String plaintext = rsaInstance.decrypt(ciphertext);
```