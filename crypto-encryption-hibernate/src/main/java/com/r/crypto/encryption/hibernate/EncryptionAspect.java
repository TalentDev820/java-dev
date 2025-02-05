package com.r.crypto.encryption.hibernate;

import com.r.crypto.encryption.exception.RCryptoEncryptionException;
import com.r.crypto.util.ThrowingSupplier;
import com.r.crypto.util.Timer;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.Signature;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static com.r.crypto.encryption.hibernate.EncryptedEntityListener.isPassthroughEnabled;
import static com.r.crypto.encryption.hibernate.EncryptedEntityListener.withPassthrough;
import static com.r.crypto.encryption.hibernate.EntityCrawler.CASCADE_SAVE;
import static org.slf4j.event.Level.INFO;

// @Aspect
// @Component
// Experimental and disabled for now
public class EncryptionAspect {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final Timer timer = new Timer(logger, RCryptoEncryptionException.class);

    private final EntityEncryptionService entityEncryptionService;

    public EncryptionAspect(EntityEncryptionService entityEncryptionService) {
        this.entityEncryptionService = entityEncryptionService;
    }

    @Pointcut("execution(* EncryptedRepository+.*(..))))")
    public void encryptedRepository() {}

    // @Pointcut("within(@EnableBatchEncryption *)")
    // public void withinBatchEncryption() {}

    @Pointcut("execution(@com.r.crypto.encryption.hibernate.EnableBatchEncryption * *(..))")
    public void batchEncryptionMethod() {}

    @Around("encryptedRepository() || batchEncryptionMethod()")
    public Object batchEncrypt(ProceedingJoinPoint joinPoint) throws Throwable {
        Signature signature = joinPoint.getSignature();
        if (signature.getDeclaringType() == Object.class || isPassthroughEnabled()) {
            return joinPoint.proceed();
        }

        String methodName = signature.getName();
        String signatureName = signature.getDeclaringType().getSimpleName() + "." + methodName;

        return timer.bracketTime(INFO, "\"%s\"", signatureName, () -> {
            Object[] args = joinPoint.getArgs();
            if (args != null && args.length > 0) {
                timer.time("encryptArgs", () -> entityEncryptionService.encrypt(CASCADE_SAVE, args));
            }

            Object result = timer.time("proceed", () -> withPassthrough((ThrowingSupplier<Object>) joinPoint::proceed));

            timer.time("decryptResult", () -> {
                if (result != null) {
                    if ((methodName.equals("save") || methodName.equals("saveAndFlush"))
                            && args != null
                            && result == args[0]) {
                        logger.debug("{} result skipped", methodName);
                    } else if (methodName.equals("saveAll")
                            && args != null
                            && args.length == 1
                            && args[0] != null
                            && args[0] instanceof Iterable) {
                        @SuppressWarnings("unchecked")
                        Iterator<Object> argsIter = ((Iterable<Object>) args[0]).iterator();
                        @SuppressWarnings("unchecked")
                        Iterator<Object> resultIter = ((Iterable<Object>) result).iterator();

                        int count = 0;
                        List<Object> mergedEntities = new ArrayList<>();
                        while (argsIter.hasNext() && resultIter.hasNext()) {
                            count++;
                            Object argsEntity = argsIter.next();
                            Object resultEntity = resultIter.next();
                            if (argsEntity != resultEntity) {
                                mergedEntities.add(resultEntity);
                            }
                        }

                        if (argsIter.hasNext() || resultIter.hasNext()) {
                            throw new IllegalStateException("arguments and result have different number of entities");
                        }

                        logger.debug("saveAll total={} new={} merged={} skipDecrypt={}",
                                count,
                                count - mergedEntities.size(),
                                mergedEntities.size(),
                                mergedEntities.isEmpty());
                        if (!mergedEntities.isEmpty()) {
                            entityEncryptionService.decrypt(CASCADE_SAVE, mergedEntities);
                        }
                    } else {
                        entityEncryptionService.decrypt(CASCADE_SAVE, result);
                    }
                }
            });

            return result;
        });
    }
}
