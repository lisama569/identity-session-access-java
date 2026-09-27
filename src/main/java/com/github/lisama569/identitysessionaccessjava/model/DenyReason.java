package com.github.lisama569.identitysessionaccessjava.model;

/**
 * 可区分的拒绝原因。登录、刷新、访问判定全部使用同一套原因码，
 * 以便调用方与审计链路对“为什么被拒绝”给出一致解释。
 */
public enum DenyReason {
    /** 用户名或口令错误（本地校验失败）。 */
    BAD_CREDENTIALS,
    /** 账户已被停用。 */
    USER_DISABLED,
    /** 请求未携带凭证或凭证格式非法。 */
    UNAUTHENTICATED,
    /** 凭证标识无法识别（不存在或签名无效）。 */
    CREDENTIAL_NOT_FOUND,
    /** 会话不存在。 */
    SESSION_NOT_FOUND,
    /** 凭证已超过有效期。 */
    CREDENTIAL_EXPIRED,
    /** 凭证已被后续刷新轮换取代。 */
    CREDENTIAL_ROTATED,
    /** 同一会话上的并发刷新竞争失败（CAS 失败）。 */
    CONCURRENT_REFRESH_CONFLICT,
    /** 凭证本身被撤销。 */
    CREDENTIAL_REVOKED,
    /** 凭证所属会话被撤销。 */
    SESSION_REVOKED,
    /** 会话因账号级容量上限被淘汰（最久未活跃者先出局），与主动撤销可区分。 */
    SESSION_CAPACITY_EVICTED,
    /** 会话超过空闲上限没有任何活动，与绝对过期（CREDENTIAL_EXPIRED）可区分。 */
    SESSION_IDLE_TIMEOUT,
    /** 已认证但权限不足。 */
    PERMISSION_DENIED
}
