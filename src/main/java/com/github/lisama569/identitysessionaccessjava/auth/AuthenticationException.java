package com.github.lisama569.identitysessionaccessjava.auth;

import com.github.lisama569.identitysessionaccessjava.model.DenyReason;

/** 登录或刷新被拒绝时抛出。 */
public class AuthenticationException extends RuntimeException {
    private final transient DenyReason reason;
    private final String credentialId;

    public AuthenticationException(DenyReason reason, String message) {
        this(reason, message, null);
    }

    public AuthenticationException(DenyReason reason, String message, String credentialId) {
        super(message);
        this.reason = reason;
        this.credentialId = credentialId;
    }

    public DenyReason getReason() { return reason; }
    public String getCredentialId() { return credentialId; }
}
