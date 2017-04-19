
# oss-keygen

***前置条件***：需要从oracle官网下载(JCE)Unlimited Strength Jurisdiction Policy Files(两个jar)放入jre的lib/security

## 构建

    mvn clean package

## 生成AES密钥 (256)

    java -jar target/oss-keygen-*-exec.jar -aes 2>/dev/null

## 生成JWT密钥 (SH512)

    java -jar target/oss-keygen-*-exec.jar -jwt 2>/dev/null

## 生成RSA密钥 (1024)

    java -jar target/oss-keygen-*-exec.jar -rsa 2>/dev/null
