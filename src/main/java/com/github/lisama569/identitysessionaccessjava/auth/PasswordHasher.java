package com.github.lisama569.identitysessionaccessjava.auth;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 本地口令哈希（salt + SHA-256）。
 *
 * <p>仅用于本地模拟凭证存储，不依赖外部身份服务，也不是生产级密码方案：
 * 真实系统应使用自适应哈希（如 Argon2/bcrypt）。这里刻意保持无外部依赖、
 * 结果确定、可在演示数据中离线预生成。</p>
 */
@Component
public class PasswordHasher {

    public String hash(String rawPassword, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt.getBytes(StandardCharsets.UTF_8));
            byte[] digest = md.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            return toHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    public boolean matches(String rawPassword, String salt, String expectedHash) {
        if (rawPassword == null || expectedHash == null) {
            return false;
        }
        return MessageDigest.isEqual(
                hash(rawPassword, salt).getBytes(StandardCharsets.UTF_8),
                expectedHash.getBytes(StandardCharsets.UTF_8));
    }

    static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
