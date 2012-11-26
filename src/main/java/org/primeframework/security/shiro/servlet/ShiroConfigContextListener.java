package org.primeframework.security.shiro.servlet;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.mgt.CachingSecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.web.env.EnvironmentLoader;
import org.apache.shiro.web.env.MutableWebEnvironment;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.primeframework.mvc.servlet.PrimeServletContextListener;

import com.google.inject.Injector;

/**
 * Extend this listener and configure it in the web.xml to setup Shiro with Guice
 *
 * @author James Humphrey
 */
public abstract class ShiroConfigContextListener implements ServletContextListener {
  @Override
  public void contextInitialized(ServletContextEvent servletContextEvent) {
    Injector injector = (Injector) servletContextEvent.getServletContext().getAttribute(PrimeServletContextListener.GUICE_INJECTOR_KEY);
    AuthorizingRealm realm = injector.getInstance(getRealmType());
    MutableWebEnvironment env = (MutableWebEnvironment) servletContextEvent.getServletContext().getAttribute(EnvironmentLoader.ENVIRONMENT_ATTRIBUTE_KEY);
    CachingSecurityManager securityManager = new DefaultWebSecurityManager(realm);
    securityManager.setCacheManager(new MemoryConstrainedCacheManager());
    env.setWebSecurityManager((DefaultWebSecurityManager) securityManager);
  }

  @Override
  public void contextDestroyed(ServletContextEvent servletContextEvent) {
  }

  public abstract Class<? extends AuthorizingRealm> getRealmType();
}
