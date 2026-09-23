package com.github.lisama569.identitysessionaccessjava.auth.store;

import com.github.lisama569.identitysessionaccessjava.auth.model.User;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 本地用户存储（内存模拟）。
 *
 * <p>仅保存用户名到用户对象的映射；用户对象内部的角色集合与属性 Map
 * 在种子数据中使用并发集合，支持运行时实时降权/改属性，判定侧无缓存。</p>
 */
@Component
public class UserStore {

    private final ConcurrentHashMap<String, User> byUsername = new ConcurrentHashMap<>();

    public User save(User user) {
        byUsername.put(user.getUsername(), user);
        return user;
    }

    public User findById(String userId) {
        return byUsername.values().stream()
                .filter(u -> u.getId().equals(userId))
                .findFirst()
                .orElse(null);
    }

    public User findByUsername(String username) {
        return byUsername.get(username);
    }

    public Collection<User> all() {
        return List.copyOf(byUsername.values());
    }
}
