/*
 * Copyright (c) 2012, Inversoft Inc., All Rights Reserved
 */
package org.primeframework.security.shiro;

import java.security.Principal;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.UnavailableSecurityManagerException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.primeframework.security.PrimeAuthenticationToken;
import org.primeframework.security.PrimePrincipal;
import org.primeframework.security.SecurityService;
import org.primeframework.security.error.InvalidCredentialsException;
import org.primeframework.security.error.PrimeSecurityException;
import org.primeframework.security.error.UndefinedPrincipalException;

/**
 * Shiro implementation of the cleanspeak security service
 *
 * @author James Humphrey
 */
public class ShiroSecurityService<T extends PrimePrincipal> implements SecurityService<T> {

  @Override
  public void login(PrimeAuthenticationToken primeAuthenticationToken) {
    if (!(primeAuthenticationToken instanceof AuthenticationToken)) {
      throw new IllegalArgumentException("login info must be an instance of " +
        AuthenticationToken.class.getCanonicalName());
    }

    if (!isLoggedIn()) {
      try {
        SecurityUtils.getSubject().login((AuthenticationToken) primeAuthenticationToken);
      } catch (IncorrectCredentialsException e) {
        throw new InvalidCredentialsException();
      } catch (AuthenticationException e) {
        if (e.getCause() instanceof UndefinedPrincipalException) {
          throw new UndefinedPrincipalException();
        } else {
          throw new PrimeSecurityException();
        }
      }
    }
  }

  @Override
  public void logout() {
    if (isLoggedIn()) {
      SecurityUtils.getSubject().logout();
    }
  }

  @Override
  public boolean isLoggedIn() {
    try {
      return SecurityUtils.getSubject().isAuthenticated();
    } catch (UnavailableSecurityManagerException e) {
      return false;
    }

  }

  @Override
  @SuppressWarnings(value = "unchecked")
  public T getPrincipals() {
    if (isLoggedIn()) {
      return (T) SecurityUtils.getSubject().getPrincipals().oneByType(Principal.class);
    } else {
      return null;
    }
  }

  @Override
  public String encryptPassword(EncryptionAlgorithm encryptionAlgorithm, String password, Object salt, int hashIterations,
                                EncodingType encodingType) {
    SimpleHash hash = new SimpleHash(encryptionAlgorithm.encryptionAlgorithm, password, salt, hashIterations);
    if (encodingType.equals(EncodingType.BASE64)) {
      return hash.toBase64();
    } else {
      return hash.toHex();
    }
  }
}
