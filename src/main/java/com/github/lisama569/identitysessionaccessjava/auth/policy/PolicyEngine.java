package com.github.lisama569.identitysessionaccessjava.auth.policy;

import com.github.lisama569.identitysessionaccessjava.auth.model.AccessDecision;
import com.github.lisama569.identitysessionaccessjava.auth.model.AccessRequest;
import com.github.lisama569.identitysessionaccessjava.auth.model.DenyReason;
import com.github.lisama569.identitysessionaccessjava.auth.model.Effect;
import com.github.lisama569.identitysessionaccessjava.auth.model.Principal;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * 基于角色（RBAC）与属性（ABAC）的判定引擎。
 *
 * <p>规则：</p>
 * <ol>
 *   <li>按注册顺序评估每条策略；资源与动作需匹配通配模式（支持 {@code *} 全通配）。</li>
 *   <li>策略同时满足：资源/动作匹配、角色任一命中（角色集为空表示不限制）、
 *       全部属性条件通过，才算命中。</li>
 *   <li>命中的 DENY 立即拒绝（显式拒绝优先）；存在命中的 ALLOW 才放行；
 *       没有任何 ALLOW 命中则以 {@link DenyReason#INSUFFICIENT_PERMISSIONS} 拒绝。</li>
 *   <li>每次判定的 basis 记录每条策略命中或失配的原因，结论可解释。</li>
 * </ol>
 *
 * <p>引擎本身不持有任何主体数据，也不缓存判定结果；主体身份由调用方实时构造，
 * 因此“已降权/已撤销”的身份不会因为缓存被放行。</p>
 */
@Component
public class PolicyEngine {

    private final List<Policy> policies = new ArrayList<>();

    public void addPolicy(Policy policy) {
        policies.add(policy);
    }

    public List<Policy> policies() {
        return List.copyOf(policies);
    }

    public AccessDecision decide(Principal subject, AccessRequest request) {
        List<String> trace = new ArrayList<>();
        boolean allowMatched = false;
        String allowBasis = null;

        for (Policy policy : policies) {
            boolean resourceOk = matches(policy.resourcePattern(), request.resource());
            boolean actionOk = matches(policy.actionPattern(), request.action());
            if (!resourceOk || !actionOk) {
                trace.add(policy.id() + ":skipped(resource/action not matched)");
                continue;
            }

            boolean roleOk = roleSatisfied(policy.anyOfRoles(), subject.roles());
            if (!roleOk) {
                trace.add(policy.id() + ":role-mismatch(requires any of "
                        + policy.anyOfRoles() + ", subject has " + subject.roles() + ")");
                continue;
            }

            List<String> failures = new ArrayList<>();
            for (AttributeCondition condition : policy.conditions()) {
                if (!condition.test(subject, request)) {
                    failures.add(condition.describe());
                }
            }
            if (!failures.isEmpty()) {
                trace.add(policy.id() + ":attribute-mismatch(" + failures + ")");
                continue;
            }

            if (policy.effect() == Effect.DENY) {
                trace.add(policy.id() + ":DENY matched");
                return AccessDecision.deny(DenyReason.INSUFFICIENT_PERMISSIONS, subject,
                        "explicit deny by policy " + policy.id() + "; trace=" + trace);
            }
            allowMatched = true;
            allowBasis = "allowed by policy " + policy.id()
                    + " (roles=" + subject.roles() + "); trace=" + trace;
            trace.add(policy.id() + ":ALLOW matched");
        }

        if (allowMatched) {
            return AccessDecision.allow(subject, allowBasis);
        }
        return AccessDecision.deny(DenyReason.INSUFFICIENT_PERMISSIONS, subject,
                "no allow policy matched; trace=" + trace);
    }

    private boolean roleSatisfied(Set<String> required, Set<String> subjectRoles) {
        if (required == null || required.isEmpty()) {
            return true;
        }
        for (String role : required) {
            if (subjectRoles.contains(role)) {
                return true;
            }
        }
        return false;
    }

    /** 仅支持精确匹配与全通配 {@code *}（如 {@code reports/*} 也按前缀通配处理）。 */
    static boolean matches(String pattern, String value) {
        if (pattern == null || "*".equals(pattern)) {
            return true;
        }
        if (value == null) {
            return false;
        }
        int star = pattern.indexOf('*');
        if (star < 0) {
            return pattern.equals(value);
        }
        String prefix = pattern.substring(0, star);
        String suffix = pattern.substring(star + 1);
        return value.startsWith(prefix) && value.endsWith(suffix)
                && value.length() >= prefix.length() + suffix.length();
    }
}
