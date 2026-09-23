package com.github.lisama569.identitysessionaccessjava.auth.service;

import com.github.lisama569.identitysessionaccessjava.auth.config.SecurityProperties;
import com.github.lisama569.identitysessionaccessjava.auth.exception.AuthDenyException;
import com.github.lisama569.identitysessionaccessjava.auth.model.AuditAction;
import com.github.lisama569.identitysessionaccessjava.auth.model.DenyReason;
import com.github.lisama569.identitysessionaccessjava.auth.model.IssuedCredential;
import com.github.lisama569.identitysessionaccessjava.auth.model.SessionInfo;
import com.github.lisama569.identitysessionaccessjava.auth.model.TokenInfo;
import com.github.lisama569.identitysessionaccessjava.auth.model.TokenStatus;
import com.github.lisama569.identitysessionaccessjava.auth.model.User;
import com.github.lisama569.identitysessionaccessjava.auth.store.SessionStore;
import com.github.lisama569.identitysessionaccessjava.auth.store.UserStore;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 认证与凭证生命周期服务（纯本地内存模拟）。
 *
 * <h3>刷新/轮换的确定性语义</h3>
 * <ol>
 *   <li>同一会话的刷新串行化（按会话加锁），锁内原子完成
 *       「旧凭证 ROTATED + 会话指针推进到新凭证」，因此同一会话任一时刻
 *       至多存在一个有效凭证，并发刷新只会有一个成功者。</li>
 *   <li>在拿到锁之前凭证仍有效、持锁后发现已被另一次刷新抢先轮换的请求，
 *       判定为 {@link DenyReason#CONCURRENTLY_ROTATED}；事后再次重放旧凭证
 *       判定为 {@link DenyReason#TOKEN_ROTATED}。两类结果可区分。</li>
 *   <li>旧凭证在轮换发生的同一临界区内即失效（{@link TokenStatus#ROTATED}，
 *       并记录 supersededBy 与 rotatedAt），失效时机确定。</li>
 * </ol>
 *
 * <h3>撤销语义</h3>
 * <ul>
 *   <li>撤销与刷新共用同一把会话锁：锁内先复核状态，杜绝“刷新覆盖撤销”或
 *       “撤销后凭证静默复活”。</li>
 *   <li>撤销即时生效（无任何判定缓存）；会话撤销后该会话再不能刷新出新凭证。</li>
 * </ul>
 */
@Service
public class AuthService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final UserStore users;
    private final SessionStore sessions;
    private final AuditService audit;
    private final Clock clock;
    private final SecurityProperties properties;

    public AuthService(UserStore users, SessionStore sessions, AuditService audit,
                       Clock clock, SecurityProperties properties) {
        this.users = users;
        this.sessions = sessions;
        this.audit = audit;
        this.clock = clock;
        this.properties = properties;
    }

    // ------------------------------------------------------------------ 登录

    public IssuedCredential login(String username, String rawPassword) {
        User user = users.findByUsername(username);
        if (user == null || !constantTimeEquals(user.getPasswordHash(), hashPassword(rawPassword))) {
            audit.emit(AuditAction.LOGIN_FAILURE, null, null, null,
                    DenyReason.BAD_CREDENTIALS, "login failed for username=" + username);
            throw new AuthDenyException(DenyReason.BAD_CREDENTIALS, null,
                    "invalid username or password");
        }
        if (!user.isEnabled()) {
            audit.emit(AuditAction.LOGIN_FAILURE, user.getId(), null, null,
                    DenyReason.USER_DISABLED, "login denied for disabled user");
            throw new AuthDenyException(DenyReason.USER_DISABLED, null, "user is disabled");
        }

        Instant now = clock.instant();
        String sessionId = newSessionId();
        ReentrantLock lock = sessions.lockFor(sessionId);
        lock.lock();
        try {
            IssuedCredential issued = issueNewToken(user, sessionId, null, 1L, now);
            audit.emit(AuditAction.LOGIN_SUCCESS, user.getId(), sessionId,
                    issued.tokenId(), null, "login success");
            return issued;
        } finally {
            lock.unlock();
        }
    }

    // -------------------------------------------------------- 刷新 / 轮换

    public IssuedCredential refresh(String secretToken) {
        TokenInfo before = sessions.tokenBySecret(secretToken);
        // 入锁前的快照旧状态：用于区分“并发竞争失败”与“事后旧凭证重放”。
        TokenStatus statusBeforeLock = before == null ? null : before.getStatus();

        if (before == null) {
            audit.emit(AuditAction.REFRESH_DENIED, null, null, null,
                    DenyReason.UNAUTHENTICATED, "unknown token presented to refresh");
            throw new AuthDenyException(DenyReason.UNAUTHENTICATED, null, "unknown token");
        }
        if (statusBeforeLock != TokenStatus.ACTIVE) {
            denyRefresh(before, persistedDeny(before, statusBeforeLock),
                    "refresh rejected before lock: status=" + statusBeforeLock);
        }

        SessionInfo session = sessions.getSession(before.getSessionId());
        ReentrantLock lock = sessions.lockFor(before.getSessionId());
        lock.lock();
        try {
            Instant now = clock.instant();

            if (session == null || session.isRevoked()) {
                denyRefresh(before, DenyReason.SESSION_REVOKED,
                        "refresh rejected: session revoked");
            }

            // 过期判定（惰性落状态，但过期时刻由 expiresAt 确定，不依赖落状态时机）。
            if (!before.getExpiresAt().isAfter(now)) {
                before.setStatus(TokenStatus.EXPIRED);
                denyRefresh(before, DenyReason.TOKEN_EXPIRED,
                        "refresh rejected: expired at " + before.getExpiresAt());
            }

            User user = users.findById(session.getUserId());
            if (user == null || !user.isEnabled()) {
                denyRefresh(before, DenyReason.USER_DISABLED,
                        "refresh rejected: user disabled or missing");
            }

            // 关键：入锁前仍 ACTIVE，持锁后发现自己已不是当前凭证，
            // 说明另一次并发刷新抢先完成 —— 明确的并发失效结论。
            if (!before.getTokenId().equals(session.getCurrentTokenId())
                    || before.getSerial() != session.getCurrentSerial()
                    || before.getStatus() != TokenStatus.ACTIVE) {
                DenyReason reason = statusBeforeLock == TokenStatus.ACTIVE
                        ? DenyReason.CONCURRENTLY_ROTATED
                        : persistedDeny(before, before.getStatus());
                denyRefresh(before, reason,
                        "refresh lost race: token serial=" + before.getSerial()
                                + ", session current serial=" + session.getCurrentSerial());
            }

            long newSerial = session.getCurrentSerial() + 1L;
            // 先记录新凭证，再在同一临界区翻转旧凭证、推进会话指针。
            IssuedCredential issued = issueNewToken(user, session.getSessionId(),
                    session, newSerial, now);
            before.setStatus(TokenStatus.ROTATED);
            before.setSupersededBy(issued.tokenId());
            before.setRotatedAt(now);

            audit.emit(AuditAction.REFRESH_SUCCESS, user.getId(), session.getSessionId(),
                    issued.tokenId(), null,
                    "rotated old tokenId=" + before.getTokenId()
                            + " serial=" + before.getSerial()
                            + " -> new serial=" + newSerial);
            return issued;
        } finally {
            lock.unlock();
        }
    }

    // --------------------------------------------------------------- 撤销

    /** 撤销单个凭证；若它仍是会话当前凭证，则该会话立即无有效凭证。 */
    public void revokeToken(String secretToken, String reason) {
        TokenInfo token = sessions.tokenBySecret(secretToken);
        if (token == null) {
            throw new AuthDenyException(DenyReason.UNAUTHENTICATED, null, "unknown token");
        }
        SessionInfo session = sessions.getSession(token.getSessionId());
        ReentrantLock lock = sessions.lockFor(token.getSessionId());
        lock.lock();
        try {
            Instant now = clock.instant();
            String userId = session == null ? null : session.getUserId();
            // 撤销语义针对整条凭证链：无论该凭证是否已被并发刷新轮换，
            // 会话都必须撤销，且会话当前凭证一并撤销，杜绝静默复活。
            if (session != null) {
                session.setRevoked(now, reason);
                TokenInfo current = sessions.tokenById(session.getCurrentTokenId());
                if (current != null && current.getStatus() == TokenStatus.ACTIVE) {
                    current.setStatus(TokenStatus.REVOKED);
                }
            }
            // 已轮换的旧凭证保留 ROTATED 状态（与“先撤销后使用”仍可区分）。
            if (token.getStatus() == TokenStatus.ACTIVE) {
                token.setStatus(TokenStatus.REVOKED);
            }
            audit.emit(AuditAction.TOKEN_REVOKED, userId, token.getSessionId(),
                    token.getTokenId(), null,
                    "token (chain) revoked: " + safe(reason)
                            + ", presentedTokenStatus=" + token.getStatus());
        } finally {
            lock.unlock();
        }
    }

    /** 撤销整段会话：会话标记撤销，其当前凭证立即 REVOKED。 */
    public void revokeSession(String sessionId, String reason) {
        SessionInfo session = sessions.getSession(sessionId);
        if (session == null) {
            throw new AuthDenyException(DenyReason.UNAUTHENTICATED, null, "unknown session");
        }
        ReentrantLock lock = sessions.lockFor(sessionId);
        lock.lock();
        try {
            Instant now = clock.instant();
            session.setRevoked(now, reason);
            TokenInfo current = sessions.tokenById(session.getCurrentTokenId());
            if (current != null && current.getStatus() == TokenStatus.ACTIVE) {
                current.setStatus(TokenStatus.REVOKED);
            }
            audit.emit(AuditAction.SESSION_REVOKED, session.getUserId(), sessionId,
                    current == null ? null : current.getTokenId(), null,
                    "session revoked: " + safe(reason));
        } finally {
            lock.unlock();
        }
    }

    /** 撤销某用户的全部会话（例如用户降权/禁用的应急处置）。 */
    public void revokeUserSessions(String userId, String reason) {
        List<SessionInfo> userSessions = sessions.sessionsOfUser(userId);
        for (SessionInfo session : userSessions) {
            revokeSession(session.getSessionId(), reason);
        }
        audit.emit(AuditAction.USER_SESSIONS_REVOKED, userId, null, null, null,
                "revoked " + userSessions.size() + " session(s): " + safe(reason));
    }

    // ------------------------------------------------------------- 内部方法

    private IssuedCredential issueNewToken(User user, String sessionId,
                                           SessionInfo existing, long serial, Instant now) {
        Instant expiresAt = now.plus(properties.getTokenTtl());
        String tokenId = newTokenId();
        String secret = newSecret();
        TokenInfo token = new TokenInfo(tokenId, secret, sessionId, serial, now, expiresAt);
        sessions.putToken(token);

        SessionInfo session = existing;
        if (session == null) {
            session = new SessionInfo(sessionId, user.getId(), now, tokenId, serial);
            sessions.putSession(session);
        } else {
            // 只允许单调向前推进，防止任何旧写覆盖新指针（防静默复活）。
            if (serial <= session.getCurrentSerial()) {
                throw new IllegalStateException(
                        "refusing to move session pointer backwards: " + serial
                                + " <= " + session.getCurrentSerial());
            }
            session.setCurrent(tokenId, serial);
        }
        audit.emit(AuditAction.TOKEN_ISSUED, user.getId(), sessionId, tokenId, null,
                "issued serial=" + serial + " expiresAt=" + expiresAt);
        return new IssuedCredential(secret, tokenId, sessionId, serial, now, expiresAt);
    }

    private void denyRefresh(TokenInfo token, DenyReason reason, String detail) {
        SessionInfo session = sessions.getSession(token.getSessionId());
        String userId = session == null ? null : session.getUserId();
        audit.emit(AuditAction.REFRESH_DENIED, userId, token.getSessionId(),
                token.getTokenId(), reason, detail);
        throw new AuthDenyException(reason, token.getTokenId(),
                "refresh denied: " + reason);
    }

    /** 已持久化状态对应的拒绝原因（事后访问/重放路径）。 */
    static DenyReason persistedDeny(TokenInfo token, TokenStatus status) {
        return switch (status) {
            case ROTATED -> DenyReason.TOKEN_ROTATED;
            case EXPIRED -> DenyReason.TOKEN_EXPIRED;
            case REVOKED -> token.getSessionId() == null
                    ? DenyReason.TOKEN_REVOKED : DenyReason.TOKEN_REVOKED;
            case ACTIVE -> null;
        };
    }

    private static String safe(String s) {
        return s == null ? "(no reason)" : s;
    }

    private static String newSessionId() {
        return "sess_" + UUID.randomUUID();
    }

    private static String newTokenId() {
        return "tok_" + UUID.randomUUID();
    }

    private static String newSecret() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    /** 模拟本地凭证：仅做 SHA-256，不依赖任何外部身份服务或真实生产凭据。 */
    public static String hashPassword(String raw) {
        if (raw == null) {
            raw = "";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(("local-demo|" + raw).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
