# 注意
1、 demo中所有的加解密都支持分段处理。

2、 注意一下填充模式

3、 私钥加密公钥解密只是为了演示可行性，要根据场景做调整使用

4、 已增加单元测试，有需要的话可以多测试几次。

5、格式化私钥到 pem 格式的时候，注意开头和结尾要用如下格式(PKCS#1)
```
-----BEGIN RSA PRIVATE KEY-----

-----END RSA PRIVATE KEY-----
```


下面这种格式为 (PKCS#8)
```
-----BEGIN PRIVATE KEY-----
BASE64 ENCODED DATA
-----END PRIVATE KEY-----
```

PKCS#1结构仅为RSA设计。X509,SSL支持的算法不仅仅是RSA，因此产生了更具有通用性的PKCS#8

https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem

https://medium.com/@oyrxx/rsa秘钥介绍及openssl生成命令-d3fcc689513f
