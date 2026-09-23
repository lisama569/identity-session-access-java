package com.github.lisama569.identitysessionaccessjava.access;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 策略注册表。判定时按权限名取出策略列表并实时求值，
 * 因此新增/变更策略对后续所有请求立即生效，不缓存判定结论。
 */
@Component
public class PolicyRegistry {

    private final List<AccessPolicy> policies = new java.util.concurrent.CopyOnWriteArrayList<>();

    public void register(AccessPolicy policy) {
        if (policy == null || policy.permission() == null) {
            throw new IllegalArgumentException("非法策略");
        }
        policies.add(policy);
    }

    public List<AccessPolicy> policiesFor(String permission) {
        if (permission == null) {
            return List.of();
        }
        return policies.stream()
                .filter(p -> permission.equals(p.permission()))
                .collect(Collectors.toUnmodifiableList());
    }

    public List<AccessPolicy> all() {
        return List.copyOf(policies);
    }
}
