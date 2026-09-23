package com.github.lisama569.identitysessionaccessjava.store;

import com.github.lisama569.identitysessionaccessjava.model.UserAccount;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 本地内存账户存储。账户的启用/停用通过 {@link UserAccount#setEnabled(boolean)}
 * 实时反映（volatile 字段），判定链路每次都重新读取，不放行已降权身份。
 */
@Repository
public class InMemoryUserStore implements UserStore {

    private final ConcurrentHashMap<String, UserAccount> byUsername = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, UserAccount> byId = new ConcurrentHashMap<>();

    @Override
    public Optional<UserAccount> findByUsername(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(byUsername.get(username));
    }

    @Override
    public Optional<UserAccount> findById(String id) {
        if (id == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(byId.get(id));
    }

    @Override
    public synchronized void save(UserAccount account) {
        if (account == null) {
            throw new IllegalArgumentException("account 不能为空");
        }
        byUsername.put(account.getUsername(), account);
        byId.put(account.getId(), account);
    }

    @Override
    public List<UserAccount> findAll() {
        return List.copyOf(byId.values());
    }
}
