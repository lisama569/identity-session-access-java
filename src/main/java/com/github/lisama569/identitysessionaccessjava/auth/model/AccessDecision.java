package com.github.lisama569.identitysessionaccessjava.auth.model;

/**
 * 判定结论：allowed + 拒绝原因 + 可解释依据 basis。
 *
 * <p>{@code basis} 用自然语言记录命中/失配的策略与条件，使每次判定都可解释；
 * 未认证等无身份场景下 principal 允许为 null。</p>
 */
public record AccessDecision(boolean allowed, DenyReason reason, String basis,
                             String userId, String sessionId, String tokenId) {

    public static AccessDecision allow(Principal principal, String basis) {
        return new AccessDecision(true, null, basis,
                principal.userId(), principal.sessionId(), principal.tokenId());
    }

    public static AccessDecision deny(DenyReason reason, Principal principal, String basis) {
        return new AccessDecision(false, reason, basis,
                principal == null ? null : principal.userId(),
                principal == null ? null : principal.sessionId(),
                principal == null ? null : principal.tokenId());
    }
}
