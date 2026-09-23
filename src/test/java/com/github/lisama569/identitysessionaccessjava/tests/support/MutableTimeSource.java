package com.github.lisama569.identitysessionaccessjava.tests.support;

import com.github.lisama569.identitysessionaccessjava.time.TimeSource;

import java.util.concurrent.atomic.AtomicLong;

/**
 * 测试用可调时钟：所有过期边界判定都基于它，因此“恰在过期时刻”等边界可精确构造。
 */
public class MutableTimeSource implements TimeSource {

    private final AtomicLong current;

    public MutableTimeSource(long startMillis) {
        this.current = new AtomicLong(startMillis);
    }

    @Override
    public long nowMillis() {
        return current.get();
    }

    public void set(long millis) {
        current.set(millis);
    }

    public void advance(long deltaMillis) {
        current.addAndGet(deltaMillis);
    }
}
