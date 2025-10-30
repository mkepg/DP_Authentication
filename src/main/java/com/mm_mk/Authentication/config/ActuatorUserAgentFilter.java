package com.mm_mk.Authentication.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class ActuatorUserAgentFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(ActuatorUserAgentFilter.class);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String path = req.getRequestURI();

        if (path.startsWith("/actuator")) {
            String ua = req.getHeader("User-Agent");
            logger.debug("Actuator access attempt - path: {}, User-Agent: {}", path, ua);

            if (ua != null && ua.matches(".*(Mozilla|Chrome|Safari|Edge).*")) {
                logger.warn("Browser access blocked to actuator - path: {}, User-Agent: {}", path, ua);
                res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                res.getWriter().write("Browser access is not allowed.");
                return;
            } else {
                logger.debug("Non-browser actuator access allowed - path: {}", path);
            }
        }
        chain.doFilter(request, response);
    }
}