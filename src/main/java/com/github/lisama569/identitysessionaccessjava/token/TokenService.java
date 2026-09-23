package com.github.lisama569.identitysessionaccessjava.token;

/**
 * 本地会话凭证签发与解析。凭证为不透明随机串加本地 HMAC 签名，
 * 不依赖任何真实凭据或外部身份服务。
 */
public interface TokenService {
    /** 生成新凭证字符串。 */
    String issueToken(String credentialId, String sessionId, String userId, long version);

    /** 解析并校验签名，返回凭证载荷；失败返回 null（等同于 CREDENTIAL_NOT_FOUND）。 */
    TokenPayload parse(String token);
}
