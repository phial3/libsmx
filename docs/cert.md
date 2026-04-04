
## 查看证书完整信息
```bash
openssl x509 -in data/www_test2_com/www.test2.com_cert.pem -text -noout
```

## 验证证书签名
```bash
openssl x509 -verify -CAfile data/www_test2_com/www.test2.com_cert.pem -in data/www_test2_com/www.test2.com_cert.pem
```

## 提取公钥
```bash
// PEM 格式公钥文件
openssl x509 -in data/www_test2_com/www.test2.com_cert.pem -pubkey -outform PEM -out www.test2.com_pub.pem -noout
// DER 格式公钥文件
openssl x509 -in data/www_test2_com/www.test2.com_cert.pem -pubkey -outform DER -out www.test2.com_pub.der -noout

// 从证书中提取公钥，转换为 DER 格式
openssl x509 -in data/www_test2_com/www.test2.com_cert.pem -pubkey -noout | openssl pkey -pubin -outform DER
```

## 查看证书 DER 编码
```bash
openssl x509 -in data/www_test2_com/www.test2.com_cert.pem -outform DER -out /tmp/www.test2.com_cert.der
```
