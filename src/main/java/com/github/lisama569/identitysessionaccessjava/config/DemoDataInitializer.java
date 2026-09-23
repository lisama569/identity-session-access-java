package com.github.lisama569.identitysessionaccessjava.config;

import com.github.lisama569.identitysessionaccessjava.access.AttributeBasedPolicy;
import com.github.lisama569.identitysessionaccessjava.access.PolicyRegistry;
import com.github.lisama569.identitysessionaccessjava.access.RoleBasedPolicy;
import com.github.lisama569.identitysessionaccessjava.auth.PasswordHasher;
import com.github.lisama569.identitysessionaccessjava.model.UserAccount;
import com.github.lisama569.identitysessionaccessjava.store.UserStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

/**
 * 初始化本地演示账户与访问策略。全部为本地模拟数据，不包含真实凭据。
 *
 * <p>账户（口令均为明文演示，存储时做 salt+SHA-256）：</p>
 * <ul>
 *   <li>alice / alice-pass：角色 USER，dept=engineering，level=5</li>
 *   <li>bob / bob-pass：角色 USER,AUDITOR，dept=finance，level=3</li>
 *   <li>admin / admin-pass：角色 USER,AUDITOR,ADMIN，dept=it，level=9</li>
 *   <li>carol / carol-pass：停用账户（enabled=false），用于验证 USER_DISABLED</li>
 * </ul>
 */
@Component
public class DemoDataInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoDataInitializer.class);

    private final UserStore userStore;
    private final PasswordHasher passwordHasher;
    private final PolicyRegistry policyRegistry;

    public DemoDataInitializer(UserStore userStore, PasswordHasher passwordHasher,
                               PolicyRegistry policyRegistry) {
        this.userStore = userStore;
        this.passwordHasher = passwordHasher;
        this.policyRegistry = policyRegistry;
    }

    @Override
    public void run(ApplicationArguments args) {
        createUser("u-alice", "alice", "alice-pass", "salt-alice",
                Set.of("USER"), Map.of("dept", "engineering", "level", "5"), true);
        createUser("u-bob", "bob", "bob-pass", "salt-bob",
                Set.of("USER", "AUDITOR"), Map.of("dept", "finance", "level", "3"), true);
        createUser("u-admin", "admin", "admin-pass", "salt-admin",
                Set.of("USER", "AUDITOR", "ADMIN"), Map.of("dept", "it", "level", "9"), true);
        createUser("u-carol", "carol", "carol-pass", "salt-carol",
                Set.of("USER"), Map.of("dept", "engineering", "level", "1"), false);

        // 角色策略（RBAC）
        policyRegistry.register(new RoleBasedPolicy("profile:read", Set.of("USER")));
        policyRegistry.register(new RoleBasedPolicy("reports:read", Set.of("AUDITOR", "ADMIN")));
        policyRegistry.register(new RoleBasedPolicy("admin:read", Set.of("ADMIN")));

        // 属性策略（ABAC）：
        // 财务报告要求 level >= 5（与 reports:read 并存，任一显式允许即放行）；
        // 工程资料要求 dept=engineering。
        policyRegistry.register(new AttributeBasedPolicy("reports:read",
                (account, resource) -> {
                    int level = parseInt(account.getAttributes().get("level"));
                    return "finance-reports".equals(resource) && level >= 5;
                }));
        policyRegistry.register(new AttributeBasedPolicy("engineering:read",
                (account, resource) -> "engineering".equals(account.getAttributes().get("dept"))));

        log.info("演示账户与策略初始化完成：alice/bob/admin(启用) carol(停用)，"
                + "权限 profile:read / reports:read / admin:read / engineering:read");
    }

    private void createUser(String id, String username, String rawPassword, String salt,
                            Set<String> roles, Map<String, String> attributes, boolean enabled) {
        String hash = passwordHasher.hash(rawPassword, salt);
        userStore.save(new UserAccount(id, username, hash, salt, Set.copyOf(roles),
                Map.copyOf(attributes), enabled));
    }

    private static int parseInt(String s) {
        try {
            return s == null ? 0 : Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
