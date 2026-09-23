package com.github.lisama569.identitysessionaccessjava.model;

/**
 * 访问判定结论。allowed=false 时 reason 一定非空，保证拒绝原因可区分、可解释。
 */
public final class AuthDecision {
    private final boolean allowed;
    private final DenyReason reason;
    private final String message;
    private final String permission;
    private final String resource;
    private final String userId;
    private final String username;
    private final String sessionId;
    private final String credentialId;

    private AuthDecision(boolean allowed, DenyReason reason, String message, String permission,
                         String resource, String userId, String username, String sessionId,
                         String credentialId) {
        this.allowed = allowed;
        this.reason = reason;
        this.message = message;
        this.permission = permission;
        this.resource = resource;
        this.userId = userId;
        this.username = username;
        this.sessionId = sessionId;
        this.credentialId = credentialId;
    }

    public static AuthDecision allow(String permission, String resource, String userId,
                                     String username, String sessionId, String credentialId) {
        return new AuthDecision(true, null, "ALLOW: 权限判定通过", permission, resource,
                userId, username, sessionId, credentialId);
    }

    public static AuthDecision deny(DenyReason reason, String message, String permission,
                                    String resource, String userId, String username,
                                    String sessionId, String credentialId) {
        return new AuthDecision(false, reason, message, permission, resource,
                userId, username, sessionId, credentialId);
    }

    public boolean isAllowed() { return allowed; }
    public DenyReason getReason() { return reason; }
    public String getMessage() { return message; }
    public String getPermission() { return permission; }
    public String getResource() { return resource; }
    public String getUserId() { return userId; }
    public String getUsername() { return username; }
    public String getSessionId() { return sessionId; }
    public String getCredentialId() { return credentialId; }
}
