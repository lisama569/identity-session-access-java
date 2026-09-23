package com.github.lisama569.identitysessionaccessjava.auth.web;

import java.time.Instant;
import java.util.Map;

/** HTTP 接口出入参模型。 */
public final class ApiModels {

    private ApiModels() {
    }

    public record LoginRequest(String username, String password) {
    }

    public record RefreshRequest(String token) {
    }

    public record RevokeRequest(String token, String reason) {
    }

    public record AccessRequestJson(String resource, String action, Map<String, String> resourceAttributes) {
    }

    public record CredentialView(String token, String tokenId, String sessionId,
                                 long serial, Instant issuedAt, Instant expiresAt) {
    }

    public record DecisionView(boolean allowed, String reason, String basis, String tokenId) {
    }

    public record ErrorView(String error, String reason, String tokenId) {
    }

    public record AuditEventView(long sequence, Instant at, String action, String userId,
                                 String sessionId, String tokenId, String reason, String detail) {
    }
}
