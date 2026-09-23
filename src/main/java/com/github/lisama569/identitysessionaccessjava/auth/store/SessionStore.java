package com.github.lisama569.identitysessionaccessjava.auth.store;

import com.github.lisama569.identitysessionaccessjava.auth.model.SessionInfo;
import com.github.lisama569.identitysessionaccessjava.auth.model.TokenInfo;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 本地会话与凭证存储（内存模拟），并提供按会话串行化的锁。
 *
 * <p>并发正确性约定：</p>
 * <ul>
 *   <li>同一会话上的刷新/轮换与撤销必须先取 {@link #lockFor(String)}，
 *       在锁内完成「校验旧凭证状态 → 翻转旧凭证 → 指向新凭证」的全过程，
 *       因此同一会话的并发刷新只会有一个成功者，撤销与刷新也不会互相覆盖。</li>
 *   <li>不同会话使用不同的锁，互不阻塞。</li>
 *   <li>凭证同时按 secret（运行时凭证）与 tokenId（日志/可观测标识）建索引。</li>
 * </ul>
 */
@Component
public class SessionStore {

    private final ConcurrentHashMap<String, SessionInfo> sessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, TokenInfo> tokensBySecret = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> secretByTokenId = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ReentrantLock> locks = new ConcurrentHashMap<>();

    public void putSession(SessionInfo session) {
        sessions.put(session.getSessionId(), session);
    }

    public SessionInfo getSession(String sessionId) {
        return sessions.get(sessionId);
    }

    public void putToken(TokenInfo token) {
        tokensBySecret.put(token.getSecret(), token);
        secretByTokenId.put(token.getTokenId(), token.getSecret());
    }

    public TokenInfo tokenBySecret(String secret) {
        if (secret == null) {
            return null;
        }
        return tokensBySecret.get(secret);
    }

    public TokenInfo tokenById(String tokenId) {
        if (tokenId == null) {
            return null;
        }
        String secret = secretByTokenId.get(tokenId);
        return secret == null ? null : tokensBySecret.get(secret);
    }

    public List<SessionInfo> sessionsOfUser(String userId) {
        List<SessionInfo> result = new ArrayList<>();
        for (SessionInfo session : sessions.values()) {
            if (session.getUserId().equals(userId)) {
                result.add(session);
            }
        }
        return result;
    }

    public Collection<SessionInfo> allSessions() {
        return List.copyOf(sessions.values());
    }

    public Collection<TokenInfo> allTokens() {
        return List.copyOf(tokensBySecret.values());
    }

    /** 获取同一会话所有状态变更共用的锁（不同会话互不影响）。 */
    public ReentrantLock lockFor(String sessionId) {
        return locks.computeIfAbsent(sessionId, k -> new ReentrantLock());
    }
}
