package com.github.lisama569.identitysessionaccessjava.auth.model;

/** 访问/刷新被拒绝时可区分的原因码。 */
public enum DenyReason {
    UNAUTHENTICATED,
    BAD_CREDENTIALS,
    TOKEN_EXPIRED,
    TOKEN_ROTATED,
    CONCURRENTLY_ROTATED,
    TOKEN_REVOKED,
    SESSION_REVOKED,
    USER_DISABLED,
    INSUFFICIENT_PERMISSIONS
}
