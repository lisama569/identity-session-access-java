package com.github.lisama569.identitysessionaccessjava.access;

import com.github.lisama569.identitysessionaccessjava.model.CredentialRecord;
import com.github.lisama569.identitysessionaccessjava.model.UserAccount;

import java.util.Objects;
import java.util.function.BiPredicate;

/**
 * 基于属性的策略：以 (账户, 资源) 谓词表达 ABAC 规则，
 * 例如 {@code (u, r) -> "engineering".equals(u.getAttributes().get("dept"))}。
 * 谓词返回 true 表示显式允许，false 表示显式拒绝（同样可解释为权限不足）。
 */
public class AttributeBasedPolicy implements AccessPolicy {

    private final String permission;
    private final BiPredicate<UserAccount, String> predicate;

    public AttributeBasedPolicy(String permission, BiPredicate<UserAccount, String> predicate) {
        this.permission = Objects.requireNonNull(permission, "permission 不能为空");
        this.predicate = Objects.requireNonNull(predicate, "predicate 不能为空");
    }

    @Override
    public String permission() {
        return permission;
    }

    @Override
    public Boolean evaluate(UserAccount account, CredentialRecord credential, String resource) {
        return predicate.test(account, resource);
    }
}
