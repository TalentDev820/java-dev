package com.r.crypto.encryption.config;

import static com.r.crypto.util.Util.toSimpleString;
import static org.springframework.context.annotation.ComponentScan.Filter;

import com.r.crypto.api.CryptoAlgorithm;
import com.r.crypto.api.kms.SimpleKms;
import com.r.crypto.api.option.TenantOption;
import com.r.crypto.encryption.api.provider.EncryptionMetricsProvider;
import com.r.crypto.encryption.api.provider.RemoteEncryptionProvider;
import com.r.crypto.encryption.api.service.EncryptionMetricsService;
import com.r.crypto.encryption.api.service.REncryptionService;
import com.r.crypto.encryption.hibernate.EncryptedEntityListener;
import com.r.crypto.encryption.migration.MigrationMode;
import com.r.crypto.provider.cipher.AesGcmCipherProvider;
import com.r.crypto.provider.cipher.LocalKmsEncryptionProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.FilterType;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;

import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Configuration
@ComponentScan(
        basePackages = "com.r.crypto.encryption.hibernate",
        // EncryptedEntityListener is created during the EntityManagerFactory component scan
        // of the SpringBeanContainer, so we need to exclude it here so we don't end up with
        // two listener beans. If it's only created here it won't actually be used by JPA.
        excludeFilters = @Filter(type = FilterType.ASSIGNABLE_TYPE, classes = EncryptedEntityListener.class)
)
@EnableAspectJAutoProxy
public class EncryptionServiceConfig {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    public static final String PROPERTY_PREFIX = "rnet.encryption.";

    @Autowired
    private Environment env;

    @Value("${rnet.encryption.vault.basePath:#{null}}")
    private String vaultBasePath;

    @Bean
    public MigrationMode defaultMigrationMode() {
        MigrationMode defaultMode = MigrationMode.valueOf(env.getProperty(PROPERTY_PREFIX + "defaultMode", "DISABLED"));
        logger.info("defaultMigrationMode=" + defaultMode);
        return defaultMode;
    }

    @Bean
    @Qualifier("tenantMigrationModes")
    public Map<String, MigrationMode> tenantMigrationModes() {
        Map<String, MigrationMode> tenantModes = new HashMap<>();
        Map<String, String> tenantModeProperties = findPropertiesByPrefix(env, PROPERTY_PREFIX + "mode");
        tenantModeProperties.forEach((entry, value) -> tenantModes.put(entry, MigrationMode.valueOf(value)));
        logger.info("tenantMigrationModes=" + tenantModes);
        return tenantModes;
    }

    @Bean("encryptionProvider")
    public RemoteEncryptionProvider testEncryptionProvider(
            Optional<EncryptionMetricsService> encryptionMetricsService
    ) throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);

        // Create LocalKms encryption keys for each virtualKey
        SimpleKms kms = new SimpleKms();
        String testTenants = env.getProperty(PROPERTY_PREFIX + "localKms.testTenants");
        Map<String, String> virtualKeyMap = findPropertiesByPrefix(env, PROPERTY_PREFIX + "virtualKey");
        virtualKeyMap.forEach((virtualKey, kmsKeyName) -> {
            // Create a key when there is no tenant
            kms.addKey(kmsKeyName, generator.generateKey());
            logger.info("created encryption key for virtualKey=" + virtualKey + " kmsKeyName=" + kmsKeyName);
            if (testTenants != null) {
                // Create a separate key for each tenant
                for (String tenant : testTenants.split(",")) {
                    logger.info("created encryption key for virtualKey=" + virtualKey + " kmsKeyName=" + kmsKeyName + " tenant=" + tenant);
                    kms.addKey(kmsKeyName, generator.generateKey(), new TenantOption(tenant));
                }
            }
        });

        RemoteEncryptionProvider provider = new LocalKmsEncryptionProvider(kms, new AesGcmCipherProvider());
        if (encryptionMetricsService.isPresent()) {
            provider = new EncryptionMetricsProvider(encryptionMetricsService.get(), provider);
        }

        logger.info("created kms=" + kms);
        logger.info("created provider=" + provider);
        return provider;
    }

    @Bean
    public REncryptionService encryptionService(@Qualifier("encryptionProvider") RemoteEncryptionProvider encryptionProvider) {
        REncryptionService encryptionService = new REncryptionService();

        CryptoAlgorithm cryptoAlgorithm = new CryptoAlgorithm("aes");
        Map<String, String> virtualKeyMap = findPropertiesByPrefix(env, PROPERTY_PREFIX + "virtualKey");
        for (Map.Entry<String, String> entry : virtualKeyMap.entrySet()) {
            encryptionService.addSymmetricKey(entry.getKey(), cryptoAlgorithm, encryptionProvider, entry.getValue());
        }

        logger.info("found encryptionProvider=" + toSimpleString(encryptionProvider));
        logger.info("created encryptionService=" + encryptionService);

        return encryptionService;
    }

    public static Map<String, String> findPropertiesByPrefix(Environment env, String prefix) {
        Map<String, String> map = new HashMap<>();

        for (PropertySource<?> propertySource : ((ConfigurableEnvironment) env).getPropertySources()) {
            if (propertySource instanceof EnumerablePropertySource) {
                for (String propertyName : ((EnumerablePropertySource<?>) propertySource).getPropertyNames()) {
                    if (propertyName.startsWith(prefix)) {
                        String tenant = propertyName.substring(prefix.length() + 1);
                        map.put(tenant, env.getProperty(propertyName));
                    }
                }
            }
        }

        return map;
    }
}
