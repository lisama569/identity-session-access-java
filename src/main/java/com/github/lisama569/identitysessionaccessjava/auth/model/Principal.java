package com.github.lisama569.identitysessionaccessjava.auth.model;

import java.util.Map;
import java.util.Set;

/** 每次判定实时构造的身份快照（角色/属性均为实时读取，不做缓存）。 */
public record Principal(String userId, String username, Set<String> roles,
                        Map<String, String> attributes, String sessionId, String tokenId) {
}
