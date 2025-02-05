package com.r.crypto.encryption.hibernate.test;

import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.encryption.api.EncryptionOperation;
import com.r.crypto.encryption.api.service.EncryptionMetricsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class TestEncryptionMetricsService implements EncryptionMetricsService {
  private final Logger logger = LoggerFactory.getLogger(getClass());
  private final List<MetricsEvent> events = new ArrayList<>();

  @Override
  public void reportEvent(
          String component,
          EncryptionOperation operation,
          KmsKey kmsKey,
          String tenant,
          long nanoTime,
          Throwable error
  ) {
    MetricsEvent event = new MetricsEvent(component, operation, kmsKey, tenant, nanoTime, error);
    logger.info("reported " + event);
    events.add(event);
  }

  public List<MetricsEvent> getEvents() {
    return events;
  }

  public void clear() {
    events.clear();
  }

  public static class MetricsEvent {
    private final String component;
    private final EncryptionOperation operation;
    private final KmsKey kmsKey;
    private final String tenant;
    private final long nanoTime;
    private final Throwable error;

    public MetricsEvent(
            String component,
            EncryptionOperation operation,
            KmsKey kmsKey,
            String tenant,
            long nanoTime,
            Throwable error
    ) {
      this.component = component;
      this.operation = operation;
      this.kmsKey = kmsKey;
      this.tenant = tenant;
      this.nanoTime = nanoTime;
      this.error = error;
    }

    public String getComponent() {
      return component;
    }

    public EncryptionOperation getOperation() {
      return operation;
    }

    public KmsKey getKmsKey() {
      return kmsKey;
    }

    public String getTenant() {
      return tenant;
    }

    public long getNanoTime() {
      return nanoTime;
    }

    public Throwable getError() {
      return error;
    }

    @Override
    public String toString() {
      return "MetricsEvent{"
              + "component='" + component + '\''
              + ", operation=" + operation
              + ", kmsKey=" + kmsKey
              + ", tenant='" + tenant + '\''
              + ", nanoTime=" + nanoTime
              + ", error=" + error
              + "}";
    }
  }
}
