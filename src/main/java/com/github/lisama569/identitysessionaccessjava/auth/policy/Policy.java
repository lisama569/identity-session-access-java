package com.github.lisama569.identitysessionaccessjava.auth.policy;

import com.github.lisama569.identitysessionaccessjava.auth.model.Effect;

import java.util.List;
import java.util.Set;

/** 一条访问策略：资源/动作通配 + 角色（任一）+ 属性条件（全部）。 */
public record Policy(String id, String resourcePattern, String actionPattern, Effect effect,
                     Set<String> anyOfRoles, List<AttributeCondition> conditions) {
}
