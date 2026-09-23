package com.github.lisama569.identitysessionaccessjava.auth.model;

import java.time.Instant;

/** 登录/刷新成功后签发的短期凭证视图。 */
public record IssuedCredential(String token, String tokenId, String sessionId,
                               long serial, Instant issuedAt, Instant expiresAt) {
}
