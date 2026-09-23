package com.github.lisama569.identitysessionaccessjava.auth.support;

import com.github.lisama569.identitysessionaccessjava.auth.config.DataSeeder;
import com.github.lisama569.identitysessionaccessjava.auth.config.SecurityProperties;
import com.github.lisama569.identitysessionaccessjava.auth.policy.PolicyEngine;
import com.github.lisama569.identitysessionaccessjava.auth.service.AccessService;
import com.github.lisama569.identitysessionaccessjava.auth.service.AuditService;
import com.github.lisama569.identitysessionaccessjava.auth.service.AuthService;
import com.github.lisama569.identitysessionaccessjava.auth.store.AuditStore;
import com.github.lisama569.identitysessionaccessjava.auth.store.SessionStore;
import com.github.lisama569.identitysessionaccessjava.auth.store.UserStore;

import java.time.Duration;

/** 纯手工组装的被测环境（含与生产一致的种子数据），并暴露可控时钟。 */
public record TestFixture(MutableClock clock,
                          SecurityProperties properties,
                          UserStore users,
                          SessionStore sessions,
                          AuditStore audits,
                          AuditService auditService,
                          AuthService auth,
                          AccessService access,
                          PolicyEngine policyEngine) {

    public static TestFixture create() {
        MutableClock clock = new MutableClock();
        SecurityProperties properties = new SecurityProperties();
        properties.setTokenTtl(Duration.ofSeconds(30));
        UserStore users = new UserStore();
        SessionStore sessions = new SessionStore();
        AuditStore audits = new AuditStore();
        AuditService auditService = new AuditService(audits, clock);
        AuthService auth = new AuthService(users, sessions, auditService, clock, properties);
        PolicyEngine policyEngine = new PolicyEngine();
        AccessService access = new AccessService(sessions, users, policyEngine, auditService, clock);
        DataSeeder seeder = new DataSeeder(users, policyEngine);
        try {
            seeder.run();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return new TestFixture(clock, properties, users, sessions, audits,
                auditService, auth, access, policyEngine);
    }
}
