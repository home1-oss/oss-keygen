package com.yirendai.oss.environment.keygen;

import static com.yirendai.oss.lib.common.crypto.CryptoConstants.COLON;
import static org.junit.Assert.assertTrue;

import com.yirendai.oss.lib.common.crypto.AesCbcKey;

import lombok.extern.slf4j.Slf4j;

import org.junit.Before;
import org.junit.Test;

/**
 * Created by zhanghaolun on 16/11/16.
 */
@Slf4j
public class KeygenTest {

  private Keygen keygen;

  @Before
  public void setUp() {
    this.keygen = new Keygen();
  }

  @Test
  public void testGenerateAesKey() {
    final String result = this.keygen.generateKey("-aes");
    log.info("testGenerateAesKey result: {}", result);
    assertTrue(result.startsWith(AesCbcKey.keySpec(256) + COLON));
  }

  @Test
  public void testGenerateJwtKey() {
    final String result = this.keygen.generateKey("-jwt");
    log.info("testGenerateJwtKey result: {}", result);
    assertTrue(result.startsWith("HS512:"));
  }

  @Test
  public void testGenerateRsaKey() {
    final String result = this.keygen.generateKey("-rsa");
    log.info("testGenerateRsaKey result: {}", result);
  }
}
