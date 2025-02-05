package com.r.crypto.encryption.hibernate.test;

import com.r.crypto.encryption.config.EncryptionServiceConfig;
import com.r.crypto.encryption.hibernate.DebugInterceptor;
import com.r.crypto.encryption.hibernate.JdbcUtil;
import com.zaxxer.hikari.HikariDataSource;
import liquibase.integration.spring.SpringLiquibase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.orm.hibernate5.SpringBeanContainer;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.JpaVendorAdapter;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.Database;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import jakarta.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import java.util.Properties;

import static com.r.crypto.util.ExceptionWrapper.wrap;
import static org.hibernate.cfg.AvailableSettings.BEAN_CONTAINER;
import static org.hibernate.cfg.AvailableSettings.INTERCEPTOR;
import static org.springframework.orm.jpa.vendor.Database.H2;
import static org.springframework.orm.jpa.vendor.Database.POSTGRESQL;

@Configuration
@EnableTransactionManagement
@EnableJpaRepositories(
        basePackages = "com.r.crypto.encryption.hibernate",
        transactionManagerRef = "RCryptoTM",
        entityManagerFactoryRef = "RCryptoEMF"
)
@PropertySource("classpath:test.properties")
@Import(EncryptionServiceConfig.class)
public class TestPersistenceConfig {
    private static final Logger logger = LoggerFactory.getLogger(TestPersistenceConfig.class);
    private static final Database database = new JdbcUtil().getDatabase();

    @Autowired
    private Environment env;

    @Bean
    public DataSource RCryptoDS() {
        return createDataSource();
    }

    @Bean
    public SpringLiquibase liquibase() {
        SpringLiquibase liquibase = new SpringLiquibase();
        liquibase.setContexts("RCryptoDB");
        liquibase.setDataSource(RCryptoDS());
        liquibase.setChangeLog("classpath:sample/changelog-master.xml");
        return liquibase;
    }

    @Bean
    public LocalContainerEntityManagerFactoryBean RCryptoEMF(ConfigurableListableBeanFactory beanFactory) {
        return createEntityManagerFactory("RCryptoPU", RCryptoDS(), beanFactory, env);
    }

    public static LocalContainerEntityManagerFactoryBean createEntityManagerFactory(
            String persistenceUnitName,
            DataSource dataSource,
            ConfigurableListableBeanFactory beanFactory,
            Environment env
    ) {
        LocalContainerEntityManagerFactoryBean factory = new LocalContainerEntityManagerFactoryBean();
        factory.setDataSource(dataSource);
        factory.setJpaVendorAdapter(createVendorAdapter(env));
        factory.setPersistenceUnitName(persistenceUnitName);
        factory.setPackagesToScan("com.r.crypto.encryption.hibernate");

        DebugInterceptor.reset();
        factory.getJpaPropertyMap().put(INTERCEPTOR, new DebugInterceptor());
        factory.getJpaPropertyMap().put(BEAN_CONTAINER, new SpringBeanContainer(beanFactory));

        return factory;
    }

    @Bean
    public JpaTransactionManager RCryptoTM(EntityManagerFactory RCryptoEMF) {
        JpaTransactionManager transactionManager = new JpaTransactionManager();
        transactionManager.setDataSource(RCryptoDS());
        transactionManager.setEntityManagerFactory(RCryptoEMF);
        return transactionManager;
    }

    public static DataSource createDataSource() {
        HikariDataSource dataSource = new HikariDataSource();

        if (database == H2) {
            logger.info("Initializing db=" + database);
            dataSource.setDataSource(new EmbeddedDatabaseBuilder()
                    .generateUniqueName(true)
                    .setType(EmbeddedDatabaseType.H2)
                    .build());
        } else {
            Properties props = new Properties();
            wrap(() -> props.load(TestPersistenceConfig.class.getClassLoader().getResourceAsStream("test.properties")));

            String propertiesPrefix = "r.crypto.db." + System.getProperty("db");
            String jdbcUrl = props.getProperty(propertiesPrefix + ".url");
            String username = props.getProperty(propertiesPrefix + ".user");

            dataSource.setJdbcUrl(jdbcUrl);
            dataSource.setUsername(username);
            dataSource.setPassword(props.getProperty(propertiesPrefix + ".password"));
            if (database == POSTGRESQL) {
                dataSource.setAutoCommit(false);
            }

            logger.info("Initializing"
                    + " db=" + database
                    + " prefix=" + propertiesPrefix
                    + " jdbcUrl=" + jdbcUrl
                    + " username=" + username);
        }

        dataSource.setMaximumPoolSize(20);

        return dataSource;
    }

    public static JpaVendorAdapter createVendorAdapter(Environment env) {
        HibernateJpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
        vendorAdapter.setDatabase(database);
        vendorAdapter.setShowSql(Boolean.parseBoolean(env.getProperty("showSQL")));
        return vendorAdapter;
    }
}
