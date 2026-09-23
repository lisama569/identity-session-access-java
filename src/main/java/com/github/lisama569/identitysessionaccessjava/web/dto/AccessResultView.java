package com.github.lisama569.identitysessionaccessjava.web.dto;

/** 对外暴露的可解释判定结果。 */
public record AccessResultView(
        boolean allowed,
        String reason,
        String message,
        String subject,
        String sessionId,
        String credentialId,
        String permission,
        String resource
) {
}
