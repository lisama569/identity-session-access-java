package com.github.lisama569.identitysessionaccessjava.auth.model;

/** 审计事件类型，覆盖登录、签发、刷新、判定与撤销全链路。 */
public enum AuditAction {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    TOKEN_ISSUED,
    REFRESH_SUCCESS,
    REFRESH_DENIED,
    ACCESS_GRANTED,
    ACCESS_DENIED,
    TOKEN_REVOKED,
    SESSION_REVOKED,
    USER_SESSIONS_REVOKED
}
