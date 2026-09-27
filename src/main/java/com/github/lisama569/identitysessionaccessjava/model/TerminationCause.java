package com.github.lisama569.identitysessionaccessjava.model;

/**
 * 会话终止原因。会话一旦被终止（无论哪种原因）即不可重新激活；
 * 该枚举只用于把“为什么被结束”以机器可读的方式区分出来。
 */
public enum TerminationCause {
    /** 主动撤销（用户登出 / 管理端踢除 / 定向结束某个设备会话）。 */
    USER_REVOKED,
    /** 账号级会话容量上限触发，最久未活跃会话被自动淘汰。 */
    CAPACITY_EVICTED
}
