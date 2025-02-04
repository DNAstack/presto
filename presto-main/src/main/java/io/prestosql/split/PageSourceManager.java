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
package io.prestosql.split;

import io.prestosql.Session;
import io.prestosql.connector.ConnectorId;
import io.prestosql.metadata.Split;
import io.prestosql.metadata.TableHandle;
import io.prestosql.spi.connector.ColumnHandle;
import io.prestosql.spi.connector.ConnectorPageSource;
import io.prestosql.spi.connector.ConnectorPageSourceProvider;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;
import static java.util.Objects.requireNonNull;

public class PageSourceManager
        implements PageSourceProvider
{
    private final ConcurrentMap<ConnectorId, ConnectorPageSourceProvider> pageSourceProviders = new ConcurrentHashMap<>();

    public void addConnectorPageSourceProvider(ConnectorId connectorId, ConnectorPageSourceProvider pageSourceProvider)
    {
        requireNonNull(connectorId, "connectorId is null");
        requireNonNull(pageSourceProvider, "pageSourceProvider is null");
        checkState(pageSourceProviders.put(connectorId, pageSourceProvider) == null, "PageSourceProvider for connector '%s' is already registered", connectorId);
    }

    public void removeConnectorPageSourceProvider(ConnectorId connectorId)
    {
        pageSourceProviders.remove(connectorId);
    }

    @Override
    public ConnectorPageSource createPageSource(Session session, Split split, TableHandle table, List<ColumnHandle> columns)
    {
        requireNonNull(columns, "columns is null");
        checkArgument(split.getConnectorId().equals(table.getConnectorId()), "mismatched split and table");
        ConnectorId connectorId = split.getConnectorId();

        return getPageSourceProvider(connectorId).createPageSource(
                table.getTransaction(),
                session.toConnectorSession(connectorId),
                split.getConnectorSplit(),
                table.getConnectorHandle(),
                columns);
    }

    private ConnectorPageSourceProvider getPageSourceProvider(ConnectorId connectorId)
    {
        ConnectorPageSourceProvider provider = pageSourceProviders.get(connectorId);
        checkArgument(provider != null, "No page source provider for connector: %s", connectorId);
        return provider;
    }
}
