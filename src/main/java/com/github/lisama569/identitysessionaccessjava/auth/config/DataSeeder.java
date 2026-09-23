package com.github.lisama569.identitysessionaccessjava.auth.config;

import com.github.lisama569.identitysessionaccessjava.auth.model.Effect;
import com.github.lisama569.identitysessionaccessjava.auth.model.User;
import com.github.lisama569.identitysessionaccessjava.auth.policy.AttributeCondition;
import com.github.lisama569.identitysessionaccessjava.auth.policy.Policy;
import com.github.lisama569.identitysessionaccessjava.auth.policy.PolicyEngine;
import com.github.lisama569.identitysessionaccessjava.auth.service.AuthService;
import com.github.lisama569.identitysessionaccessjava.auth.store.UserStore;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 预置本地用户与策略的种子数据（仅内存模拟，无外部数据源）。
 *
 * <p>用户：</p>
 * <ul>
 *   <li>{@code alice / alice-pw}：admin，拥有 department=platform、level=5</li>
 *   <li>{@code bob / bob-pw}：auditor，department=ops、level=2</li>
 *   <li>{@code carol / carol-pw}：viewer，department=ops、level=1</li>
 *   <li>{@code dave / dave-pw}：被禁用用户</li>
 * </ul>
 *
 * <p>角色集合使用并发集合，测试可实时移除角色以验证“降权即时生效”。</p>
 */
@Component
public class DataSeeder implements CommandLineRunner {

    private final UserStore users;
    private final PolicyEngine policyEngine;

    public DataSeeder(UserStore users, PolicyEngine policyEngine) {
        this.users = users;
        this.policyEngine = policyEngine;
    }

    @Override
    public void run(String... args) {
        users.save(new User("u-alice", "alice", AuthService.hashPassword("alice-pw"),
                concurrentSet("admin", "auditor", "viewer"),
                new ConcurrentHashMap<>(Map.of("department", "platform", "level", "5")), true));
        users.save(new User("u-bob", "bob", AuthService.hashPassword("bob-pw"),
                concurrentSet("auditor", "viewer"),
                new ConcurrentHashMap<>(Map.of("department", "ops", "level", "2")), true));
        users.save(new User("u-carol", "carol", AuthService.hashPassword("carol-pw"),
                concurrentSet("viewer"),
                new ConcurrentHashMap<>(Map.of("department", "ops", "level", "1")), true));
        users.save(new User("u-dave", "dave", AuthService.hashPassword("dave-pw"),
                concurrentSet("viewer"),
                new ConcurrentHashMap<>(Map.of("department", "ops", "level", "1")), false));

        // 1. admin 可管理全部资源（RBAC）。
        policyEngine.addPolicy(new Policy("p-admin-all", "*", "*", Effect.ALLOW,
                Set.of("admin"), List.of()));

        // 2. auditor 可读取 reports 下任意资源（RBAC）。
        policyEngine.addPolicy(new Policy("p-auditor-read-reports", "reports/*", "read",
                Effect.ALLOW, Set.of("auditor"), List.of()));

        // 3. viewer 只能读 public 资源（RBAC）。
        policyEngine.addPolicy(new Policy("p-viewer-read-public", "public/*", "read",
                Effect.ALLOW, Set.of("viewer"), List.of()));

        // 4. ABAC：仅当主体与资源同部门时可读取部门文档。
        AttributeCondition sameDepartment = new AttributeCondition() {
            @Override
            public boolean test(com.github.lisama569.identitysessionaccessjava.auth.model.Principal subject,
                                com.github.lisama569.identitysessionaccessjava.auth.model.AccessRequest request) {
                String subjectDept = subject.attributes().get("department");
                String resourceDept = request.resourceAttributes().get("department");
                return subjectDept != null && subjectDept.equals(resourceDept);
            }

            @Override
            public String describe() {
                return "subject.department == resource.department";
            }
        };
        policyEngine.addPolicy(new Policy("p-same-dept-docs", "docs/*", "read", Effect.ALLOW,
                Set.of(), List.of(sameDepartment)));

        // 5. 显式拒绝：任何人都不得删除审计日志（即使 admin 也被显式拒绝）。
        policyEngine.addPolicy(new Policy("p-deny-audit-delete", "audit/*", "delete",
                Effect.DENY, Set.of(), List.of()));
    }

    private static Set<String> concurrentSet(String... roles) {
        Set<String> set = ConcurrentHashMap.newKeySet();
        set.addAll(List.of(roles));
        return set;
    }
}
