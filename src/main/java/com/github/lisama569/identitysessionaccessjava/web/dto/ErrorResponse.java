package com.github.lisama569.identitysessionaccessjava.web.dto;

import com.github.lisama569.identitysessionaccessjava.model.DenyReason;

public record ErrorResponse(
        boolean allowed,
        DenyReason reason,
        String message,
        String resource,
        String credentialId,
        long timestamp
) {
}
