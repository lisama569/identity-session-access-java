package com.github.lisama569.identitysessionaccessjava.access;

import com.github.lisama569.identitysessionaccessjava.model.AuthDecision;

/**
 * 统一访问判定：先认证（凭证/会话状态实时读取，绝不放行缓存身份），
 * 再授权（至少一条策略显式允许，否则 PERMISSION_DENIED）。
 */
public interface AccessControlService {
    AuthDecision decide(String presentedToken, String permission, String resource);
    AuthDecision requireAllowed(String presentedToken, String permission, String resource);
}
