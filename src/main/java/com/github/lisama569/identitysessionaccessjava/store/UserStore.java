package com.github.lisama569.identitysessionaccessjava.store;

import com.github.lisama569.identitysessionaccessjava.model.UserAccount;

import java.util.List;
import java.util.Optional;

/** 本地账户存储。 */
public interface UserStore {
    Optional<UserAccount> findByUsername(String username);
    Optional<UserAccount> findById(String id);
    void save(UserAccount account);
    List<UserAccount> findAll();
}
