package com.github.lisama569.identitysessionaccessjava.access;

import com.github.lisama569.identitysessionaccessjava.model.CredentialRecord;
import com.github.lisama569.identitysessionaccessjava.model.UserAccount;

/**
 * 基于角色或属性的访问策略。返回 null 表示本策略不表态（中立）。
 */
public interface AccessPolicy {
    String permission();
    /** null = 不表态，true = 允许，false = 拒绝。 */
    Boolean evaluate(UserAccount account, CredentialRecord credential, String resource);
}
