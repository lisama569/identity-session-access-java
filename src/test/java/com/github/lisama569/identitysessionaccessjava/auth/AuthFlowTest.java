package com.github.lisama569.identitysessionaccessjava.auth;

import com.github.lisama569.identitysessionaccessjava.auth.exception.AuthDenyException;
import com.github.lisama569.identitysessionaccessjava.auth.model.DenyReason;
import com.github.lisama569.identitysessionaccessjava.auth.model.IssuedCredential;
import com.github.lisama569.identitysessionaccessjava.auth.support.TestFixture;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

/** 登录签发与正常轮换链路：凭证标识、serial 单调、旧凭证确定失效。 */
class AuthFlowTest {

    private static final Logger log = LoggerFactory.getLogger(AuthFlowTest.class);

    @Test
    void loginIssuesShortLivedCredentialAndRefreshRotatesIt() {
        TestFixture f = TestFixture.create();

        IssuedCredential first = f.auth().login("alice", "alice-pw");
        log.info("[AUTH] login ok, sessionId={} tokenId={} serial={} expiresAt={}",
                first.sessionId(), first.tokenId(), first.serial(), first.expiresAt());
        assertEquals(1L, first.serial());
        assertNotNull(first.token());
        assertEquals(first.tokenId(), f.sessions().tokenBySecret(first.token()).getTokenId());

        IssuedCredential second = f.auth().refresh(first.token());
        log.info("[AUTH] refresh ok, oldTokenId={} -> newTokenId={} newSerial={}",
                first.tokenId(), second.tokenId(), second.serial());
        assertEquals(first.sessionId(), second.sessionId());
        assertEquals(2L, second.serial());

        // 会话指针唯一指向新凭证，旧凭证在轮换临界区内已确定失效。
        assertEquals(second.tokenId(),
                f.sessions().getSession(first.sessionId()).getCurrentTokenId());

        AuthDenyException replay = assertThrows(AuthDenyException.class,
                () -> f.auth().refresh(first.token()));
        log.info("[AUTH] replay old tokenId={} denied reason={}",
                first.tokenId(), replay.getReason());
        assertEquals(DenyReason.TOKEN_ROTATED, replay.getReason());
        assertEquals(first.tokenId(), replay.getTokenId());

        // 新凭证仍可继续轮换，serial 继续单调。
        IssuedCredential third = f.auth().refresh(second.token());
        assertEquals(3L, third.serial());
        AuthDenyException replay2 = assertThrows(AuthDenyException.class,
                () -> f.auth().refresh(second.token()));
        assertEquals(DenyReason.TOKEN_ROTATED, replay2.getReason());
    }

    @Test
    void badPasswordAndDisabledUserHaveDistinctReasons() {
        TestFixture f = TestFixture.create();

        AuthDenyException bad = assertThrows(AuthDenyException.class,
                () -> f.auth().login("alice", "wrong"));
        log.info("[AUTH] bad credentials username=alice reason={}", bad.getReason());
        assertEquals(DenyReason.BAD_CREDENTIALS, bad.getReason());

        AuthDenyException unknown = assertThrows(AuthDenyException.class,
                () -> f.auth().login("ghost", "x"));
        assertEquals(DenyReason.BAD_CREDENTIALS, unknown.getReason());

        AuthDenyException disabled = assertThrows(AuthDenyException.class,
                () -> f.auth().login("dave", "dave-pw"));
        log.info("[AUTH] disabled user=dave reason={}", disabled.getReason());
        assertEquals(DenyReason.USER_DISABLED, disabled.getReason());

        AuthDenyException noToken = assertThrows(AuthDenyException.class,
                () -> f.auth().refresh("not-a-real-secret"));
        assertEquals(DenyReason.UNAUTHENTICATED, noToken.getReason());
    }
}
