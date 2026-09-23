package com.github.lisama569.identitysessionaccessjava.access;

import com.github.lisama569.identitysessionaccessjava.model.AuthDecision;

/** 访问被拒绝时抛出，携带完整的可解释判定结论。 */
public class AuthorizationException extends RuntimeException {
    private final transient AuthDecision decision;

    public AuthorizationException(AuthDecision decision) {
        super(decision.getMessage());
        this.decision = decision;
    }

    public AuthDecision getDecision() {
        return decision;
    }
}
