package org.primeframework.security.error;

import org.primeframework.mvc.ErrorException;
import org.primeframework.security.PrimePrincipal;

/**
 * Thrown when princiapls are undefined.  See {@link PrimePrincipal#isDefined()} for further details
 *
 * @author James Humphrey
 */
public class UndefinedPrincipalException extends ErrorException {
}
