package com.github.lisama569.identitysessionaccessjava.auth.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** 测试用可控时钟：时间只在测试显式推进时变化，使过期边界确定可测。 */
public class MutableClock extends Clock {

    private volatile Instant now = Instant.parse("2026-09-24T00:00:00Z");

    @Override
    public Instant instant() {
        return now;
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }

    public void advance(Duration duration) {
        this.now = this.now.plus(duration);
    }

    public void setInstant(Instant instant) {
        this.now = instant;
    }
}
