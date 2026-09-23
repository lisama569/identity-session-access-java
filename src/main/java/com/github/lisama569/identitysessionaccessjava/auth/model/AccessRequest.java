package com.github.lisama569.identitysessionaccessjava.auth.model;

import java.util.Map;

/** 一次资源访问请求及其资源侧属性（供 ABAC 判定）。 */
public record AccessRequest(String resource, String action, Map<String, String> resourceAttributes) {
}
