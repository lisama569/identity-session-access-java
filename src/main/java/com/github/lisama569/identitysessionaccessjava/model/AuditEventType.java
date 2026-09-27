package com.github.lisama569.identitysessionaccessjava.model;

/** 审计事件类型，覆盖登录、刷新、访问、撤销四条链路。 */
public enum AuditEventType {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    REFRESH_SUCCESS,
    REFRESH_FAILURE,
    ACCESS_ALLOWED,
    ACCESS_DENIED,
    SESSION_REVOKED,
    CREDENTIAL_REVOKED,
    SESSION_CAPACITY_EVICTED
}
