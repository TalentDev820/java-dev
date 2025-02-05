package com.r.crypto.encryption.hibernate.test;

import com.r.crypto.encryption.api.service.EncryptionMetricsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TestMetricsConfig {
  private final Logger logger = LoggerFactory.getLogger(getClass());

  @Bean
  public EncryptionMetricsService encryptionMetricsService() {
    TestEncryptionMetricsService metricsService = new TestEncryptionMetricsService();
    logger.info("created metricsService=" + metricsService);
    return metricsService;
  }
}
