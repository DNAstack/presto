/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.prestosql.server.security;

import io.prestosql.spi.security.BasicPrincipal;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import java.security.Principal;

public class HealthUrlAuthenticator
        implements Authenticator
{
    private final HealthUrlConfig config;

    @Inject
    public HealthUrlAuthenticator(HealthUrlConfig config)
    {
        this.config = config;
    }

    @Override
    public Principal authenticate(HttpServletRequest request) throws AuthenticationException
    {
        String requestedPath = request.getPathInfo();
        String allowedPath = config.getHealthCheckUrl();
        if (allowedPath.equals(requestedPath)) {
            return new BasicPrincipal("Anon Health-Check");
        }
        throw new AuthenticationException("Not a health-check URL: " + requestedPath);
    }
}
