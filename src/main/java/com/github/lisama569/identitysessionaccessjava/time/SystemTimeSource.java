package com.github.lisama569.identitysessionaccessjava.time;

import org.springframework.stereotype.Component;

/** 生产环境时钟，直接读取系统时间。 */
@Component
public class SystemTimeSource implements TimeSource {
    @Override
    public long nowMillis() {
        return System.currentTimeMillis();
    }
}
