package com.github.lisama569.identitysessionaccessjava.auth.exception;

import com.github.lisama569.identitysessionaccessjava.auth.model.DenyReason;

/** 可区分原因的认证/刷新拒绝异常。 */
public class AuthDenyException extends RuntimeException {

    private final DenyReason reason;
    private final String tokenId;

    public AuthDenyException(DenyReason reason, String tokenId, String message) {
        super(message);
        this.reason = reason;
        this.tokenId = tokenId;
    }

    public DenyReason getReason() { return reason; }
    public String getTokenId() { return tokenId; }
}
