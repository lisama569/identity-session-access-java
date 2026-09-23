package com.github.lisama569.identitysessionaccessjava.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

/** 安全相关配置（凭证有效期等）。 */
@Component
@ConfigurationProperties(prefix = "app.security")
public class SecurityProperties {

    private Duration tokenTtl = Duration.ofSeconds(60);

    public Duration getTokenTtl() { return tokenTtl; }
    public void setTokenTtl(Duration tokenTtl) { this.tokenTtl = tokenTtl; }
}
