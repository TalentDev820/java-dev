package com.r.crypto.service.encryption.impl.vault;

import com.r.crypto.exception.RCryptoException;
import com.r.crypto.util.Timer;
import org.slf4j.Logger;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.vault.authentication.SessionManager;
import org.springframework.vault.client.VaultEndpointProvider;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.web.client.RestTemplate;

import static com.r.crypto.util.Util.quote;
import static org.slf4j.event.Level.INFO;

@SuppressWarnings("NullableProblems")
public class LoggingVaultTemplate extends VaultTemplate {
    private final Timer timer;

    public LoggingVaultTemplate(
            VaultEndpointProvider endpointProvider,
            ClientHttpRequestFactory requestFactory,
            SessionManager sessionManager,
            Logger logger
    ) {
        super(endpointProvider, requestFactory, sessionManager);
        this.timer = new Timer(logger, INFO, RCryptoException.class);
    }

    @Override
    protected RestTemplate doCreateRestTemplate(
            @NonNull VaultEndpointProvider endpointProvider,
            @NonNull ClientHttpRequestFactory requestFactory
    ) {
        return addLogger(super.doCreateRestTemplate(endpointProvider, requestFactory));
    }

    @Override
    protected RestTemplate doCreateSessionTemplate(
            @NonNull VaultEndpointProvider endpointProvider,
            @NonNull ClientHttpRequestFactory requestFactory
    ) {
        return addLogger(super.doCreateSessionTemplate(endpointProvider, requestFactory));
    }

    private RestTemplate addLogger(RestTemplate restTemplate) {
        restTemplate.getInterceptors().add(new RequestResponseLoggingInterceptor());
        return restTemplate;
    }

    private class RequestResponseLoggingInterceptor implements ClientHttpRequestInterceptor {
        @Override
        public ClientHttpResponse intercept(
                @NonNull HttpRequest request,
                @NonNull byte[] body,
                @NonNull ClientHttpRequestExecution execution
        ) {
            return timer.time(
                    () -> request.getMethod() + " url=" + quote(request.getURI()),
                    () -> execution.execute(request, body)
            );
        }
    }
}
