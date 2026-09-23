package com.github.lisama569.identitysessionaccessjava.auth.model;

import java.util.Map;
import java.util.Set;

/** 本地用户：模拟凭证（加盐摘要）、实时角色与属性、启用标志。 */
public final class User {

    private final String id;
    private final String username;
    private volatile String passwordHash;
    private final Set<String> roles;
    private final Map<String, String> attributes;
    private volatile boolean enabled;

    public User(String id, String username, String passwordHash,
                Set<String> roles, Map<String, String> attributes, boolean enabled) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.roles = roles;
        this.attributes = attributes;
        this.enabled = enabled;
    }

    public String getId() { return id; }
    public String getUsername() { return username; }
    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
    public Set<String> getRoles() { return roles; }
    public Map<String, String> getAttributes() { return attributes; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
}
