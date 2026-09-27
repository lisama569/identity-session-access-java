package com.github.lisama569.identitysessionaccessjava.model;

/**
 * 会话被结束的类别。用于把“主动撤销”与“容量淘汰”在拒绝原因上区分开；
 * 空闲超时属于惰性判定（不落撤销位），不在此枚举内。
 */
public enum RevokeKind {
    /** 未被结束。 */
    NONE,
    /** 显式撤销（用户登出 / 管理端撤销 / 定向结束某会话）。 */
    EXPLICIT,
    /** 账号会话容量超限，按“最久未活跃先出局”被自动结束。 */
    CAPACITY
}
