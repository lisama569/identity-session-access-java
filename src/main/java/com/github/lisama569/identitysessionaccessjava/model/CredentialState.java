package com.github.lisama569.identitysessionaccessjava.model;

/**
 * 凭证生命周期状态。状态迁移只能由明确的事件触发：
 * ACTIVE -> ROTATED（刷新成功）/ REVOKED（撤销）/ EXPIRED（惰性过期标记）；
 * ROTATED -> REVOKED（会话级撤销连带旧凭证）。
 */
public enum CredentialState {
    ACTIVE,
    ROTATED,
    EXPIRED,
    REVOKED
}
