package com.github.lisama569.identitysessionaccessjava.store;

import com.github.lisama569.identitysessionaccessjava.model.CredentialRecord;
import com.github.lisama569.identitysessionaccessjava.model.CredentialState;
import com.github.lisama569.identitysessionaccessjava.model.SessionInfo;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * 本地内存会话存储。
 *
 * <p>以 {@link ConcurrentHashMap#computeIfAbsent} 为每个会话分配一把独立锁，
 * 所有“读-判-写”复合操作（刷新轮换、会话撤销）都在该锁内完成；
 * 锁对象一旦创建永不移除，避免锁被替换导致的并发窗口。</p>
 */
@Repository
public class InMemorySessionStore implements SessionStore {

    private final ConcurrentHashMap<String, SessionInfo> sessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, CredentialRecord> credentials = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<String>> sessionCredentialIds = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> locks = new ConcurrentHashMap<>();
    /**
     * 每个会话当前刷新批次的参与者请求标识集合（begin 时锁外登记，end 时锁内移除）。
     */
    private final ConcurrentHashMap<String, java.util.Set<String>> refreshBatches =
            new ConcurrentHashMap<>();
    /**
     * 最近一次成功轮换在锁内快照的同批并发竞争者名单。名单只在整个批次结束
     * （在途集合清空）时清除，保证排队靠后的输家在赢家释放锁后仍被正确识别。
     */
    private final ConcurrentHashMap<String, java.util.Set<String>> lastRotationLosers =
            new ConcurrentHashMap<>();

    @Override
    public synchronized void create(SessionInfo session, CredentialRecord credential) {
        if (session == null || credential == null) {
            throw new IllegalArgumentException("session 与 credential 不能为空");
        }
        sessions.put(session.getId(), session);
        credentials.put(credential.getId(), credential);
        List<String> ids = Collections.synchronizedList(new ArrayList<>());
        ids.add(credential.getId());
        sessionCredentialIds.put(session.getId(), ids);
    }

    @Override
    public Optional<SessionInfo> findSession(String sessionId) {
        return sessionId == null ? Optional.empty() : Optional.ofNullable(sessions.get(sessionId));
    }

    @Override
    public Optional<CredentialRecord> findCredential(String credentialId) {
        return credentialId == null ? Optional.empty()
                : Optional.ofNullable(credentials.get(credentialId));
    }

    @Override
    public List<CredentialRecord> credentialsOfSession(String sessionId) {
        List<String> ids = sessionCredentialIds.get(sessionId);
        if (ids == null) {
            return List.of();
        }
        List<CredentialRecord> result = new ArrayList<>();
        synchronized (ids) {
            for (String id : ids) {
                CredentialRecord c = credentials.get(id);
                if (c != null) {
                    result.add(c);
                }
            }
        }
        return List.copyOf(result);
    }

    @Override
    public <T> T withSessionLock(String sessionId, Function<SessionInfo, T> action) {
        Object lock = locks.computeIfAbsent(sessionId, k -> new Object());
        synchronized (lock) {
            SessionInfo session = sessions.get(sessionId);
            return action.apply(session);
        }
    }

    @Override
    public String beginRefreshAttempt(String sessionId, String requestId) {
        refreshBatches.computeIfAbsent(sessionId,
                k -> java.util.concurrent.ConcurrentHashMap.newKeySet()).add(requestId);
        return sessionId;
    }

    @Override
    public void endRefreshAttempt(String batchHandle, String requestId) {
        if (batchHandle == null) {
            return;
        }
        Object lock = locks.computeIfAbsent(batchHandle, k -> new Object());
        synchronized (lock) {
            java.util.Set<String> batch = refreshBatches.get(batchHandle);
            if (batch != null) {
                batch.remove(requestId);
                if (batch.isEmpty()) {
                    refreshBatches.remove(batchHandle);
                    // 批次彻底结束：清除并发输家名单。此后旧凭证再来即事后重放。
                    lastRotationLosers.remove(batchHandle);
                }
            }
        }
    }

    @Override
    public RefreshOutcome atomicRefresh(String batchHandle, String requestId,
                                        String presentedCredentialId,
                                        CredentialRecord newCredential, long nowMillis) {
        if (presentedCredentialId == null || newCredential == null) {
            throw new IllegalArgumentException("参数不能为空");
        }
        CredentialRecord presented = credentials.get(presentedCredentialId);
        if (presented == null) {
            return RefreshOutcome.of(RefreshOutcome.Kind.PRESENTED_NOT_FOUND, null);
        }
        String sessionId = presented.getSessionId();
        Object lock = locks.computeIfAbsent(sessionId, k -> new Object());
        synchronized (lock) {
            SessionInfo session = sessions.get(sessionId);
            if (session == null) {
                return RefreshOutcome.of(RefreshOutcome.Kind.SESSION_NOT_FOUND, null);
            }
            return doRefresh(session, requestId, presented, newCredential, nowMillis);
        }
    }

    /** 必须在会话级锁内调用。 */
    private RefreshOutcome doRefresh(SessionInfo session, String requestId,
                                     CredentialRecord presented, CredentialRecord newCredential,
                                     long nowMillis) {
        String sessionId = session.getId();
        // 1) 撤销优先于一切（含过期与轮换）
        if (session.isRevoked() || presented.getState() == CredentialState.REVOKED) {
            return RefreshOutcome.of(RefreshOutcome.Kind.REVOKED,
                    session.getCurrentCredentialId());
        }
        // 2) 过期其次（边界 now >= expiresAt）
        if (presented.isExpiredAt(nowMillis)) {
            return RefreshOutcome.of(RefreshOutcome.Kind.EXPIRED,
                    session.getCurrentCredentialId());
        }
        boolean isCurrent = presented.getId().equals(session.getCurrentCredentialId());
        if (!isCurrent || presented.getState() == CredentialState.ROTATED) {
            // 权威分类（与线程调度、时间窗无关）：
            //  a) 本请求在赢家提交轮换时已登记在批次中 -> 出现在并发输家名单；
            //  b) 本请求进入锁时批次仍有其他未完成参与者（赢家尚未 end）-> 同批并发。
            java.util.Set<String> losers = lastRotationLosers.get(sessionId);
            java.util.Set<String> batch = refreshBatches.get(sessionId);
            boolean recordedLoser = losers != null && losers.contains(requestId);
            boolean peerInBatch = batch != null && batch.stream()
                    .anyMatch(other -> !other.equals(requestId));
            if (recordedLoser || peerInBatch) {
                if (presented.getState() != CredentialState.REVOKED) {
                    presented.setState(CredentialState.ROTATED);
                    if (presented.getReplacedByCredentialId() == null) {
                        presented.setReplacedByCredentialId(session.getCurrentCredentialId());
                    }
                }
                return RefreshOutcome.of(RefreshOutcome.Kind.CONCURRENT_LOSS,
                        session.getCurrentCredentialId());
            }
            return RefreshOutcome.of(RefreshOutcome.Kind.SUPERSEDED_REPLAY,
                    session.getCurrentCredentialId());
        }
        // ---- 提交轮换（与上述判定同一把锁，对外为一次原子切换）----
        presented.setState(CredentialState.ROTATED);
        presented.setReplacedByCredentialId(newCredential.getId());
        credentials.put(newCredential.getId(), newCredential);
        List<String> list = sessionCredentialIds.get(sessionId);
        if (list == null) {
            throw new IllegalStateException("会话凭证索引缺失: " + sessionId);
        }
        synchronized (list) {
            list.add(newCredential.getId());
        }
        session.rotate(newCredential.getId(), newCredential.getVersion());
        // 在锁内快照同批竞争者：begin 在屏障之后、任何服务调用之前完成，
        // 因此此刻批次中的其他请求必然是并发竞争者，而非事后重放。
        java.util.Set<String> batch = refreshBatches.get(sessionId);
        if (batch != null) {
            java.util.Set<String> snapshot = new java.util.HashSet<>(batch);
            snapshot.remove(requestId);
            lastRotationLosers.computeIfAbsent(sessionId,
                    k -> java.util.concurrent.ConcurrentHashMap.newKeySet()).addAll(snapshot);
        }
        return RefreshOutcome.success(newCredential);
    }

    @Override
    public List<CredentialRecord> atomicRevokeSession(String sessionId, String reason, long nowMillis) {
        if (sessionId == null) {
            return null;
        }
        Object lock = locks.computeIfAbsent(sessionId, k -> new Object());
        synchronized (lock) {
            SessionInfo session = sessions.get(sessionId);
            if (session == null) {
                return null;
            }
            // markRevoked 保留首次撤销原因，保证并发撤销不互相覆盖
            session.markRevoked(nowMillis, reason);
            List<CredentialRecord> changed = new ArrayList<>();
            for (CredentialRecord c : credentialsOfSession(sessionId)) {
                if (c.getState() != CredentialState.REVOKED) {
                    c.setState(CredentialState.REVOKED);
                    changed.add(c);
                }
            }
            return List.copyOf(changed);
        }
    }

    @Override
    public boolean atomicRevokeCredential(String credentialId, String reason, long nowMillis) {
        if (credentialId == null) {
            return false;
        }
        CredentialRecord c = credentials.get(credentialId);
        if (c == null) {
            return false;
        }
        Object lock = locks.computeIfAbsent(c.getSessionId(), k -> new Object());
        synchronized (lock) {
            // 双重检查，防止拿到引用后被并发删除（当前实现不删除，但保持语义严谨）
            c = credentials.get(credentialId);
            if (c == null) {
                return false;
            }
            if (c.getState() == CredentialState.REVOKED) {
                return true;
            }
            c.setState(CredentialState.REVOKED);
            return true;
        }
    }

}
