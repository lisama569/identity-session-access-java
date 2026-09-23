package com.github.lisama569.identitysessionaccessjava.token;

/** 凭证解析结果。 */
public record TokenPayload(String credentialId, String sessionId, String userId, long version) {
}
