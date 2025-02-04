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
package io.prestosql.testing;

import io.prestosql.connector.ConnectorId;
import io.prestosql.metadata.TableHandle;
import io.prestosql.testing.TestingMetadata.TestingTableHandle;

import java.util.Optional;

public final class TestingHandles
{
    private TestingHandles() {}

    public static final TableHandle TEST_TABLE_HANDLE = new TableHandle(
            new ConnectorId("test"),
            new TestingTableHandle(),
            TestingTransactionHandle.create(),
            Optional.of(TestingHandle.INSTANCE));
}
