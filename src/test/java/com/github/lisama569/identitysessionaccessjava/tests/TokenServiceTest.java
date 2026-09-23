package com.github.lisama569.identitysessionaccessjava.tests;

import com.github.lisama569.identitysessionaccessjava.token.LocalHmacTokenService;
import com.github.lisama569.identitysessionaccessjava.token.TokenPayload;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 本地凭证签发/解析测试：合法可解析，签名或内容被篡改一律无法识别。
 */
class TokenServiceTest {

    private static final Logger log = LoggerFactory.getLogger(TokenServiceTest.class);

    private final LocalHmacTokenService tokens = new LocalHmacTokenService("unit-test-secret");

    @Test
    void issueAndParseRoundTrip() {
        String token = tokens.issueToken("cred-001", "sess-001", "u-1", 3L);
        TokenPayload payload = tokens.parse(token);
        assertNotNull(payload);
        assertEquals("cred-001", payload.credentialId());
        assertEquals("sess-001", payload.sessionId());
        assertEquals("u-1", payload.userId());
        assertEquals(3L, payload.version());
        log.info("凭证标识(credentialId)={} 判定依据=HMAC 签名校验通过, version={}",
                payload.credentialId(), payload.version());
    }

    @Test
    void tamperedSignatureIsRejected() {
        String token = tokens.issueToken("cred-002", "sess-002", "u-2", 1L);
        char last = token.charAt(token.length() - 1);
        char flipped = last == 'A' ? 'B' : 'A';
        String tampered = token.substring(0, token.length() - 1) + flipped;
        assertNull(tokens.parse(tampered), "签名被篡改必须无法识别");
        log.info("凭证标识(credentialId)=cred-002 判定依据=签名不匹配 -> CREDENTIAL_NOT_FOUND");
    }

    @Test
    void garbageAndNullAreRejected() {
        assertNull(tokens.parse("not-a-token"));
        assertNull(tokens.parse(""));
        assertNull(tokens.parse(null));
        log.info("凭证标识=null/非法 判定依据=格式或签名无效 -> UNAUTHENTICATED/CREDENTIAL_NOT_FOUND");
    }

    @Test
    void secretMismatchRejects() {
        String token = new LocalHmacTokenService("secret-a")
                .issueToken("cred-003", "sess-003", "u-3", 1L);
        assertNull(new LocalHmacTokenService("secret-b").parse(token));
        log.info("凭证标识(credentialId)=cred-003 判定依据=不同密钥下 HMAC 校验失败");
    }
}
