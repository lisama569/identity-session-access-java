package com.github.lisama569.identitysessionaccessjava.store;

import com.github.lisama569.identitysessionaccessjava.model.CredentialRecord;
import com.github.lisama569.identitysessionaccessjava.model.RevokeKind;
import com.github.lisama569.identitysessionaccessjava.model.SessionInfo;

import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * 本地会话与凭证存储。
 *
 * <p><b>一致性契约：</b>“校验旧凭证 + 旧凭证置 ROTATED + 新凭证入库 +
 * 会话当前指针切换”必须在同一个会话级锁内一次完成（见
 * {@link #atomicRefresh}）；会话撤销与其名下凭证撤销同样在锁内一次完成
 * （见 {@link #atomicRevokeSession}）。因此并发刷新只有一个赢家，
 * 并发撤销/刷新不会互相覆盖状态。</p>
 */
public interface SessionStore {

    /** 登录建会话：会话与其首张凭证一起入库。 */
    void create(SessionInfo session, CredentialRecord credential);

    /**
     * 登录建会话并原子执行账号容量淘汰。整个“建会话 + 超限淘汰”在账号级锁内
     * 一次完成：并发登录收敛后，该账号活跃会话数不超过 maxActiveSessions。
     * 淘汰规则：按 lastActiveAt 升序，最久未活跃者先出局；新会话活跃时间最新，
     * 不会淘汰自己。被淘汰会话在锁内标记撤销（类别 CAPACITY）并连带凭证失效。
     *
     * @return 本次被淘汰的会话（可能为空）
     */
    List<SessionInfo> atomicCreateSession(SessionInfo session, CredentialRecord credential,
                                          int maxActiveSessions, long nowMillis);

    /** 列出账号名下全部会话（含已结束），调用方自行过滤活跃会话。 */
    List<SessionInfo> sessionsOfAccount(String userId);

    Optional<SessionInfo> findSession(String sessionId);

    Optional<CredentialRecord> findCredential(String credentialId);

    /** 列出会话名下全部凭证（含已轮换、已撤销），供会话级撤销使用。 */
    List<CredentialRecord> credentialsOfSession(String sessionId);

    /**
     * 以会话为锁单位执行原子读改写，动作内可安全修改会话与凭证状态。
     *
     * @return action 的返回值；会话不存在时返回 null
     */
    <T> T withSessionLock(String sessionId, Function<SessionInfo, T> action);

    /**
     * 登记一次刷新尝试的开始（在获取会话锁之前调用）。
     * 返回的 opaque 批次句柄需原样传给 {@link #atomicRefresh}，
     * 使存储层能把“同批并发竞争失败者”与“轮换结束后的旧凭证重放”权威区分。
     */
    String beginRefreshAttempt(String sessionId, String requestId);

    /**
     * 原子刷新轮换。调用方先通过 {@link #beginRefreshAttempt} 登记批次；
     * 身份/状态/当前指针的全部权威判定都在会话锁内完成，结果由 {@link RefreshOutcome} 表达。
     * 兼容重载：不做空闲判定（等价于空闲上限无限大）。
     */
    default RefreshOutcome atomicRefresh(String batchHandle, String requestId,
                                         String presentedCredentialId, CredentialRecord newCredential,
                                         long nowMillis) {
        return atomicRefresh(batchHandle, requestId, presentedCredentialId, newCredential,
                nowMillis, Long.MAX_VALUE);
    }

    /**
     * 原子刷新轮换（含空闲判定）。撤销 &gt; 绝对过期 &gt; 空闲超时 &gt; 轮换/并发
     * 的优先级在会话锁内权威判定；成功时在锁内将会话 lastActiveAt 顺延到 now。
     */
    RefreshOutcome atomicRefresh(String batchHandle, String requestId,
                                 String presentedCredentialId, CredentialRecord newCredential,
                                 long nowMillis, long idleTimeoutMillis);

    /** 刷新尝试结束（无论成功失败），释放批次占位。 */
    void endRefreshAttempt(String batchHandle, String requestId);

    /**
     * 原子撤销会话：锁内标记会话 REVOKED，并把名下所有非撤销凭证置为 REVOKED。
     *
     * @return 被连带撤销（状态发生迁移）的凭证；会话不存在返回 null
     */
    default List<CredentialRecord> atomicRevokeSession(String sessionId, String reason, long nowMillis) {
        return atomicRevokeSession(sessionId, reason, RevokeKind.EXPLICIT, nowMillis);
    }

    /**
     * 原子结束会话（带结束类别）：锁内标记会话 REVOKED 并记录 {@link RevokeKind}，
     * 把名下所有非撤销凭证置为 REVOKED。重复结束保留首次类别与原因。
     *
     * @return 被连带撤销（状态发生迁移）的凭证；会话不存在返回 null
     */
    List<CredentialRecord> atomicRevokeSession(String sessionId, String reason, RevokeKind kind,
                                               long nowMillis);

    /** 撤销单张凭证（凭证级撤销）；凭证不存在返回 false。 */
    boolean atomicRevokeCredential(String credentialId, String reason, long nowMillis);

    /** 原子刷新结果。 */
    final class RefreshOutcome {
        public enum Kind {
            /** 刷新成功，新凭证已成为会话当前指针。 */
            SUCCESS,
            /** 出示凭证标识在存储中不存在。 */
            PRESENTED_NOT_FOUND,
            /** 会话不存在。 */
            SESSION_NOT_FOUND,
            /** 会话已撤销或出示凭证已撤销（撤销优先于一切）。 */
            REVOKED,
            /**
             * 并发刷新竞争失败：进入锁时出示凭证仍为 ACTIVE 但已不是当前指针。
             * 这是“同会话并发刷新只允许一个赢家”的确定信号。
             */
            CONCURRENT_LOSS,
            /**
             * 事后重放：进入锁时出示凭证已是 ROTATED（上一次轮换已提交）。
             */
            SUPERSEDED_REPLAY,
            /** 进入锁时凭证已过期（边界 now &gt;= expiresAt）。 */
            EXPIRED,
            /** 进入锁时会话空闲超时（now - lastActiveAt &gt;= idleTimeoutMillis）。 */
            IDLE_EXPIRED
        }

        private final Kind kind;
        private final CredentialRecord newCredential;
        private final String currentCredentialId;

        private RefreshOutcome(Kind kind, CredentialRecord newCredential, String currentCredentialId) {
            this.kind = kind;
            this.newCredential = newCredential;
            this.currentCredentialId = currentCredentialId;
        }

        public static RefreshOutcome success(CredentialRecord c) {
            return new RefreshOutcome(Kind.SUCCESS, c, c.getId());
        }

        public static RefreshOutcome of(Kind kind, String currentCredentialId) {
            return new RefreshOutcome(kind, null, currentCredentialId);
        }

        public Kind kind() { return kind; }
        public CredentialRecord newCredential() { return newCredential; }
        public String currentCredentialId() { return currentCredentialId; }
    }
}
