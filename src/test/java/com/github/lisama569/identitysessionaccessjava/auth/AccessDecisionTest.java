package com.github.lisama569.identitysessionaccessjava.auth;

import com.github.lisama569.identitysessionaccessjava.auth.model.AccessDecision;
import com.github.lisama569.identitysessionaccessjava.auth.model.AccessRequest;
import com.github.lisama569.identitysessionaccessjava.auth.model.DenyReason;
import com.github.lisama569.identitysessionaccessjava.auth.model.IssuedCredential;
import com.github.lisama569.identitysessionaccessjava.auth.model.User;
import com.github.lisama569.identitysessionaccessjava.auth.support.TestFixture;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 权限判定测试：RBAC、ABAC、显式拒绝优先、默认拒绝，以及“实时降权即时生效”。
 *
 * <p>所有断言都打印凭证标识与判定依据 basis，确保结论可解释。</p>
 */
class AccessDecisionTest {

    private static final Logger log = LoggerFactory.getLogger(AccessDecisionTest.class);

    private void explain(String label, AccessDecision d) {
        log.info("[ACCESS] {} tokenId={} allowed={} reason={} basis={}",
                label, d.tokenId(), d.allowed(),
                d.reason() == null ? "-" : d.reason(), d.basis());
    }

    @Test
    void rbacDecisionsAreExplainableAndDistinct() {
        TestFixture f = TestFixture.create();
        IssuedCredential alice = f.auth().login("alice", "alice-pw");
        IssuedCredential bob = f.auth().login("bob", "bob-pw");
        IssuedCredential carol = f.auth().login("carol", "carol-pw");

        AccessRequest adminOp = new AccessRequest("system/config", "write", Map.of());
        AccessRequest readReport = new AccessRequest("reports/2026Q3", "read", Map.of());
        AccessRequest readPublic = new AccessRequest("public/welcome", "read", Map.of());

        AccessDecision a = f.access().authorize(alice.token(), adminOp);
        explain("alice admin-write", a);
        assertTrue(a.allowed());

        AccessDecision b1 = f.access().authorize(bob.token(), readReport);
        explain("bob read-reports", b1);
        assertTrue(b1.allowed());

        AccessDecision b2 = f.access().authorize(bob.token(), adminOp);
        explain("bob admin-write", b2);
        assertFalse(b2.allowed());
        assertEquals(DenyReason.INSUFFICIENT_PERMISSIONS, b2.reason());
        assertTrue(b2.basis().contains("no allow policy matched"));

        AccessDecision c1 = f.access().authorize(carol.token(), readPublic);
        explain("carol read-public", c1);
        assertTrue(c1.allowed());

        AccessDecision c2 = f.access().authorize(carol.token(), readReport);
        explain("carol read-reports", c2);
        assertFalse(c2.allowed());
        assertEquals(DenyReason.INSUFFICIENT_PERMISSIONS, c2.reason());
    }

    @Test
    void abacMatchesDepartmentAttribute() {
        TestFixture f = TestFixture.create();
        IssuedCredential bob = f.auth().login("bob", "bob-pw");

        AccessRequest sameDept = new AccessRequest("docs/runbook", "read",
                Map.of("department", "ops"));
        AccessRequest otherDept = new AccessRequest("docs/runbook", "read",
                Map.of("department", "platform"));

        AccessDecision ok = f.access().authorize(bob.token(), sameDept);
        explain("bob docs same-dept", ok);
        assertTrue(ok.allowed());
        assertTrue(ok.basis().contains("p-same-dept-docs"));

        AccessDecision no = f.access().authorize(bob.token(), otherDept);
        explain("bob docs other-dept", no);
        assertFalse(no.allowed());
        assertEquals(DenyReason.INSUFFICIENT_PERMISSIONS, no.reason());
        assertTrue(no.basis().contains("subject.department == resource.department"));
    }

    @Test
    void explicitDenyOverridesAdminAllow() {
        TestFixture f = TestFixture.create();
        IssuedCredential alice = f.auth().login("alice", "alice-pw");
        AccessRequest deleteAudit = new AccessRequest("audit/logs", "delete", Map.of());

        AccessDecision d = f.access().authorize(alice.token(), deleteAudit);
        explain("alice delete-audit", d);
        assertFalse(d.allowed());
        assertEquals(DenyReason.INSUFFICIENT_PERMISSIONS, d.reason());
        assertTrue(d.basis().contains("explicit deny by policy p-deny-audit-delete"));
    }

    @Test
    void liveRoleRemovalTakesEffectImmediatelyWithoutCache() {
        TestFixture f = TestFixture.create();
        IssuedCredential bob = f.auth().login("bob", "bob-pw");
        AccessRequest readReport = new AccessRequest("reports/secret", "read", Map.of());

        AccessDecision before = f.access().authorize(bob.token(), readReport);
        explain("bob before de-role", before);
        assertTrue(before.allowed());

        // 模拟实时降权：直接从用户当前角色集合移除 auditor（同一会话、同一凭证仍在）。
        User user = f.users().findByUsername("bob");
        boolean removed = user.getRoles().remove("auditor");
        assertTrue(removed);

        AccessDecision after = f.access().authorize(bob.token(), readReport);
        explain("bob after de-role", after);
        assertFalse(after.allowed(), "降权后不得因缓存而放行");
        assertEquals(DenyReason.INSUFFICIENT_PERMISSIONS, after.reason());
        assertEquals(bob.tokenId(), after.tokenId(), "被降权的仍是同一张凭证");
    }

    @Test
    void disablingUserImmediatelyStopsAccess() {
        TestFixture f = TestFixture.create();
        IssuedCredential bob = f.auth().login("bob", "bob-pw");
        AccessRequest readReport = new AccessRequest("reports/x", "read", Map.of());
        assertTrue(f.access().authorize(bob.token(), readReport).allowed());

        f.users().findByUsername("bob").setEnabled(false);
        AccessDecision d = f.access().authorize(bob.token(), readReport);
        explain("bob after disable", d);
        assertFalse(d.allowed());
        assertEquals(DenyReason.USER_DISABLED, d.reason());
    }
}
