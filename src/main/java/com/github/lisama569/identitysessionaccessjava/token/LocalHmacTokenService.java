package com.github.lisama569.identitysessionaccessjava.token;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * 基于本地 HMAC-SHA256 的不透明会话凭证。
 *
 * <p>令牌结构：{@code base64url(payload) + "." + base64url(hmac(payload))}，
 * payload 为 {@code credentialId.sessionId.userId.version}。
 * 凭证字符串本身只用于定位凭证记录；是否有效完全由本地会话/凭证状态决定，
 * 因此状态撤销或轮换后，即使令牌签名仍合法也会被拒绝——不存在“凭签名复活”。</p>
 */
@Service
public class LocalHmacTokenService implements TokenService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final byte[] secret;
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final Base64.Decoder decoder = Base64.getUrlDecoder();

    public LocalHmacTokenService(
            @Value("${identity.token.secret:local-dev-secret-change-me}") String secret) {
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public String issueToken(String credentialId, String sessionId, String userId, long version) {
        String payload = String.join(".", credentialId, sessionId, userId, Long.toString(version));
        String encoded = encoder.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        return encoded + "." + encoder.encodeToString(sign(encoded));
    }

    @Override
    public TokenPayload parse(String token) {
        if (token == null) {
            return null;
        }
        String[] parts = token.split("\\.", 2);
        if (parts.length != 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
            return null;
        }
        byte[] expected = sign(parts[0]);
        byte[] provided;
        try {
            provided = decoder.decode(parts[1]);
        } catch (IllegalArgumentException e) {
            return null;
        }
        // 常量时间比较，避免签名伪造的时序侧信道
        if (!MessageDigest.isEqual(expected, provided)) {
            return null;
        }
        String payload;
        try {
            payload = new String(decoder.decode(parts[0]), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
        String[] fields = payload.split("\\.", 4);
        if (fields.length != 4) {
            return null;
        }
        try {
            return new TokenPayload(fields[0], fields[1], fields[2], Long.parseLong(fields[3]));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private byte[] sign(String encodedPayload) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret, HMAC_ALGORITHM));
            return mac.doFinal(encodedPayload.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC 签名失败", e);
        }
    }
}
