package com.yirendai.oss.environment.keygen;

import com.yirendai.oss.lib.common.crypto.AesCbcKey;
import com.yirendai.oss.lib.common.crypto.AesKeyGenerator;
import com.yirendai.oss.lib.common.crypto.JwtKeyGenerator;
import com.yirendai.oss.lib.common.crypto.RsaKeys;

import org.springframework.boot.Banner;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.builder.SpringApplicationBuilder;

public class Keygen implements CommandLineRunner {

  public static void main(final String... args) {
    new SpringApplicationBuilder()
        .sources(Keygen.class)
        .bannerMode(Banner.Mode.OFF)
        .run(args);
  }

  @Override
  public void run(final String... args) throws Exception {
    if (args.length == 0) {
      System.err.println(this.usage());
    } else {
      final String option = args[0];
      final String result = this.generateKey(option);
      if (result != null) {
        System.out.print(result);
      } else {
        System.err.println(this.usage());
      }
    }
  }

  public String generateKey(final String option) {
    final String spec;
    final String result;
    switch (option) {
      case "-aes":
        spec = AesCbcKey.keySpec(256);
        result = new AesKeyGenerator(spec).generateKey().toString();
        break;
      case "-jwt":
        spec = "HS512";
        result = new JwtKeyGenerator(spec).generateKey().toString();
        break;
      case "-rsa":
        final int keySize = 1024;
        result = RsaKeys.generateRsaKey(keySize);
        break;
      // support "-jks" ?
      default:
        result = null;
        break;
    }
    return result;
  }

  private String usage() {
    return "" + //
        "Usage: java -jar yrd-lib-common-*.jar [OPTION]\n" + //
        "\t-aes\n" + //
        "\t\tgenerate random AES CBC key\n" + //
        "\t-jwt\n" + //
        "\t\tgenerate random JWT HS512 key\n" + //
        "\t-rsa\n" + //
        "\t\tgenerate random RSA1024 key\n" + //
        "";
  }
}
