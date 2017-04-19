package com.yirendai.oss.lib.common.crypto;

import static com.yirendai.oss.lib.common.CodecUtils.decodeBase64;
import static com.yirendai.oss.lib.common.crypto.CryptoConstants.COLON;
import static com.yirendai.oss.lib.common.crypto.RsaKey.KEY_FORMAT_PKCS1;
import static com.yirendai.oss.lib.common.crypto.RsaKey.KEY_FORMAT_PKCS8;
import static com.yirendai.oss.lib.common.crypto.RsaKey.KEY_FORMAT_PKCS8_X509;
import static com.yirendai.oss.lib.common.crypto.RsaKey.KEY_FORMAT_X509;
import static com.yirendai.oss.lib.common.crypto.RsaKey.KEY_TYPE_PAIR;
import static com.yirendai.oss.lib.common.crypto.RsaKey.KEY_TYPE_PRIVATE;
import static com.yirendai.oss.lib.common.crypto.RsaKey.KEY_TYPE_PUBLIC;
import static com.yirendai.oss.lib.common.crypto.RsaKey.extractPrivateKey;
import static com.yirendai.oss.lib.common.crypto.RsaKey.extractPublicKey;
import static com.yirendai.oss.lib.common.crypto.RsaKey.keySize;
import static com.yirendai.oss.lib.common.crypto.RsaKey.keySpec;
import static com.yirendai.oss.lib.common.crypto.RsaKeyGenerator.pem;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static lombok.AccessLevel.PRIVATE;
import static org.apache.commons.io.FileUtils.writeStringToFile;

import com.yirendai.oss.lib.common.CodecUtils;

import lombok.NoArgsConstructor;
import lombok.SneakyThrows;

import java.io.File;

/**
 * Created by zhanghaolun on 16/11/13.
 */
@NoArgsConstructor(access = PRIVATE)
public abstract class RsaKeys {

  public static String generateRsaKey(final int keySize) {
    final String spec = RsaKey.keySpec(KEY_FORMAT_PKCS8_X509, keySize, KEY_TYPE_PAIR);
    final RsaKeyGenerator rsaKeyGenerator = new RsaKeyGenerator(spec);
    final KeyExpression pairPkcs8X509 = rsaKeyGenerator.generateKey();
    final KeyExpression pairPkcs1 = RsaKeyGenerator.convertPairFromPkcs8X509ToPkcs1(pairPkcs8X509);

    final StringBuilder result = new StringBuilder();
    //
    System.err.println("privateKey PKCS8: " + writePemFile(pairPkcs8X509, KEY_FORMAT_PKCS8, KEY_TYPE_PRIVATE));
    final String privateKeyPkcs1PemFile = writePemFile(pairPkcs1, KEY_FORMAT_PKCS1, KEY_TYPE_PRIVATE);
    System.err.println("privateKey PKCS1: " + privateKeyPkcs1PemFile);
    System.err.println("Check with command line OpenSSL that the key format is as expected:");
    System.err.println("openssl rsa -in " + privateKeyPkcs1PemFile + " -noout -text");
    //
    System.err.println("publicKey  x509: " + writePemFile(pairPkcs8X509, KEY_FORMAT_X509, KEY_TYPE_PUBLIC));
    System.err.println("publicKey PKCS1: " + writePemFile(pairPkcs1, KEY_FORMAT_PKCS1, KEY_TYPE_PUBLIC));
    //
    return result //
        .append(pairPkcs8X509.toString()).append("\n") //
        .append(pairPkcs1.toString()).append("\n") //
        .append(keySpec(KEY_TYPE_PRIVATE, keySize, KEY_FORMAT_PKCS1)).append(COLON) //
        .append(extractPrivateKey(pairPkcs1)).append("\n") //
        .append(keySpec(KEY_TYPE_PRIVATE, keySize, KEY_FORMAT_PKCS8)).append(COLON) //
        .append(extractPrivateKey(pairPkcs8X509)).append("\n") //
        .append(keySpec(KEY_TYPE_PUBLIC, keySize, KEY_FORMAT_PKCS1)).append(COLON) //
        .append(extractPublicKey(pairPkcs1)).append("\n") //
        .append(keySpec(KEY_TYPE_PUBLIC, keySize, KEY_FORMAT_X509)).append(COLON) //
        .append(extractPublicKey(pairPkcs8X509)) //
        .toString();
  }

  public static File keyFile(final String keyFormat, final int keySize, final String keyType) {
    //final String targetDirectory = System.getProperty("java.io.tmpdir", "/tmp");
    final String targetDirectory = System.getProperty("user.dir", "/tmp");
    return new File(targetDirectory + "/" + keySpec(keyType, keySize, keyFormat) + ".pem");
  }

  @SneakyThrows
  public static String writePemFile(final KeyExpression pair, final String keyFormat, final String keyType) {
    final int keySize = keySize(pair.getSpec());
    final File pemFile = keyFile(keyFormat, keySize, keyType);
    final byte[] bytes = CodecUtils.decodeBase64(KEY_TYPE_PRIVATE.equals(keyType) ? //
        extractPrivateKey(pair) : extractPublicKey(pair));
    writeStringToFile(pemFile, pem(bytes, keyFormat, keyType), US_ASCII);
    return pemFile.getPath();
  }
}
