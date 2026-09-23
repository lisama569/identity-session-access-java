package com.github.lisama569.identitysessionaccessjava.web;

/**
 * 当前请求原始凭证（Bearer Token）持有者，由过滤器写入、控制器读取、请求结束清理。
 */
public final class CurrentCredentialHolder {
    private static final ThreadLocal<String> TOKEN = new ThreadLocal<>();

    private CurrentCredentialHolder() {
    }

    public static void set(String token) {
        TOKEN.set(token);
    }

    public static String get() {
        return TOKEN.get();
    }

    public static void clear() {
        TOKEN.remove();
    }
}
