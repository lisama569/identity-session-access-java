package com.github.lisama569.identitysessionaccessjava.auth.model;

/** 凭证在会话内的单向状态机：ACTIVE -> ROTATED / EXPIRED / REVOKED。 */
public enum TokenStatus {
    ACTIVE,
    ROTATED,
    EXPIRED,
    REVOKED
}
