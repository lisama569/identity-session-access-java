package com.github.lisama569.identitysessionaccessjava.time;

/**
 * 可注入时钟。所有过期判定只依赖该时钟，使过期边界在测试中可确定。
 */
public interface TimeSource {
    long nowMillis();
}
