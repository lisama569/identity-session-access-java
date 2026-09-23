package com.github.lisama569.identitysessionaccessjava.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 仅负责提取 {@code Authorization: Bearer <token>} 头并放入 ThreadLocal。
 *
 * <p>过滤器本身不做任何认证/授权决策：所有入口一律由
 * {@code AccessControlService.decide()} 给出唯一结论，避免“过滤器放行、
 * 控制器另行判定”造成的不一致或缓存放行。</p>
 */
@Component
public class BearerTokenFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            String header = request.getHeader("Authorization");
            if (header != null && header.startsWith(BEARER_PREFIX)) {
                String token = header.substring(BEARER_PREFIX.length()).trim();
                if (!token.isEmpty()) {
                    CurrentCredentialHolder.set(token);
                }
            }
            filterChain.doFilter(request, response);
        } finally {
            // 确保线程复用不串号
            CurrentCredentialHolder.clear();
        }
    }
}
