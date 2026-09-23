package com.github.lisama569.identitysessionaccessjava.access;

import com.github.lisama569.identitysessionaccessjava.model.CredentialRecord;
import com.github.lisama569.identitysessionaccessjava.model.UserAccount;

import java.util.Objects;
import java.util.Set;

/**
 * 基于角色的策略：账户拥有 allowRoles 中任意一个角色即显式允许。
 * 角色集合每次从账户对象实时读取，账户被降权后新的判定立即生效。
 */
public class RoleBasedPolicy implements AccessPolicy {

    private final String permission;
    private final Set<String> allowRoles;

    public RoleBasedPolicy(String permission, Set<String> allowRoles) {
        this.permission = Objects.requireNonNull(permission, "permission 不能为空");
        this.allowRoles = Set.copyOf(allowRoles);
    }

    @Override
    public String permission() {
        return permission;
    }

    @Override
    public Boolean evaluate(UserAccount account, CredentialRecord credential, String resource) {
        if (account == null || account.getRoles() == null) {
            return null;
        }
        for (String role : allowRoles) {
            if (account.getRoles().contains(role)) {
                return Boolean.TRUE;
            }
        }
        return null;
    }

    public Set<String> getAllowRoles() {
        return allowRoles;
    }
}
