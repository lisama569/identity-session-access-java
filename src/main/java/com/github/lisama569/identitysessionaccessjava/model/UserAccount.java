package com.github.lisama569.identitysessionaccessjava.model;

import java.util.Map;
import java.util.Set;

/**
 * 本地用户账户。口令以本地盐值哈希形式模拟存储，不依赖任何外部身份服务。
 */
public final class UserAccount {
    private final String id;
    private final String username;
    private final String passwordHash;
    private final String passwordSalt;
    private final Set<String> roles;
    private final Map<String, String> attributes;
    private volatile boolean enabled;

    public UserAccount(String id, String username, String passwordHash, String passwordSalt,
                       Set<String> roles, Map<String, String> attributes, boolean enabled) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.passwordSalt = passwordSalt;
        this.roles = roles;
        this.attributes = attributes;
        this.enabled = enabled;
    }

    public String getId() { return id; }
    public String getUsername() { return username; }
    public String getPasswordHash() { return passwordHash; }
    public String getPasswordSalt() { return passwordSalt; }
    public Set<String> getRoles() { return roles; }
    public Map<String, String> getAttributes() { return attributes; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
}
