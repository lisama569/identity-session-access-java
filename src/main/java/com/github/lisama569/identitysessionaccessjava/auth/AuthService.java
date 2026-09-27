package com.github.lisama569.identitysessionaccessjava.auth;

import com.github.lisama569.identitysessionaccessjava.model.CredentialRecord;
import com.github.lisama569.identitysessionaccessjava.model.SessionInfo;
import com.github.lisama569.identitysessionaccessjava.web.dto.SessionView;
import com.github.lisama569.identitysessionaccessjava.web.dto.TokenResponse;

import java.util.List;

/**
 * 登录、刷新（轮换）、撤销、会话治理。
 */
public interface AuthService {
    TokenResponse login(String username, String rawPassword);
    TokenResponse refresh(String presentedToken);

    /**
     * 加入某会话的并发刷新批次。对一批需要并发执行的刷新，请先让所有线程调用本方法，
     * 再同时调用 {@link #refresh(String)}；系统据此权威区分“并发竞争失败”与
     * “轮换结束后的旧凭证重放”。单请求路径无需显式调用。
     *
     * @return 批次句柄（不透明）
     */
    Object joinRefreshBatch(String presentedToken);

    /** 退出并发刷新批次，必须与 {@link #joinRefreshBatch} 配对。 */
    void leaveRefreshBatch(Object batchHandle);

    void revokeSession(String sessionId, String reason);
    void revokeCredential(String credentialId, String reason);

    /**
     * 列出账号名下当前活跃（未终止、未绝对过期、未空闲超时）的会话，
     * 供多设备会话治理使用；账号不存在时返回空列表。
     */
    List<SessionView> listActiveSessions(String username);

    /** 仅供解析展示/内部使用。 */
    SessionInfo requireSession(String sessionId);
    CredentialRecord requireCredential(String credentialId);
}
