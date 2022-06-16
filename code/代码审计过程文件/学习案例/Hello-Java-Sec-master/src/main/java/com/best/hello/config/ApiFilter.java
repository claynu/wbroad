package com.best.hello.config;

import io.netty.util.internal.StringUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@WebFilter(filterName = "apiFilter",urlPatterns = "/*")
public class ApiFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        log.info("--ApiFilter init--");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        log.info("--ApiFilter in--");

        //参数过滤逻辑
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        String query = request.getQueryString();
        if(this.isDangerSqlStr(query)){
            return;
        }


        filterChain.doFilter(servletRequest,servletResponse);
        log.info("--ApiFilter out--");
    }

    @Override
    public void destroy() {
        log.info("--ApiFilter destroy--");

    }
    private boolean isDangerSqlStr(String query){
        if (Objects.isNull(query)|| StringUtil.isNullOrEmpty(query)){
            return false;
        }
        String regex = "(--|#|%22|'|%27|\")";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(query);
        log.info("request.getQueryString() = {}",query);
        if (matcher.find()){
            log.error("Dangerous Character");
            return true;
        }
        return false;
    }
}
