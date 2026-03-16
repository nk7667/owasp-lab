package org.owasplab.security;

import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
public class LoginLockService {

    private static class State {
        int failCount;
        long lockedUntilMs;
    }

    private final ConcurrentMap<String, State> states = new ConcurrentHashMap<>();

    private final int maxFails = 5;
    private final long lockDurationMs = 60_000L; // 60 秒，方便你测试

    public boolean isLocked(String username) {
        State s = states.get(username);
        if (s == null) return false;

        long now = System.currentTimeMillis();
        synchronized (s) {
            if (s.lockedUntilMs <= 0) return false;
            if (now >= s.lockedUntilMs) {
                // 到期自动解锁并清零
                s.lockedUntilMs = 0;
                s.failCount = 0;
                return false;
            }
            return true;
        }
    }

    public long retryAfterSeconds(String username) {
        State s = states.get(username);
        if (s == null) return 0;
        long now = System.currentTimeMillis();
        synchronized (s) {
            if (s.lockedUntilMs <= 0) return 0;
            long remainMs = s.lockedUntilMs - now;
            return remainMs <= 0 ? 0 : (remainMs + 999) / 1000;
        }
    }

    public int onFailure(String username) {
        State s = states.computeIfAbsent(username, k -> new State());
        long now = System.currentTimeMillis();
        synchronized (s) {
            // 若已过期，先清零
            if (s.lockedUntilMs > 0 && now >= s.lockedUntilMs) {
                s.lockedUntilMs = 0;
                s.failCount = 0;
            }

            s.failCount++;

            if (s.failCount >= maxFails) {
                s.lockedUntilMs = now + lockDurationMs;
            }
            return s.failCount;
        }
    }

    public void onSuccess(String username) {
        State s = states.get(username);
        if (s == null) return;
        synchronized (s) {
            s.failCount = 0;
            s.lockedUntilMs = 0;
        }
    }

    public int getFailCount(String username) {
        State s = states.get(username);
        if (s == null) return 0;
        synchronized (s) {
            return s.failCount;
        }
    }
}