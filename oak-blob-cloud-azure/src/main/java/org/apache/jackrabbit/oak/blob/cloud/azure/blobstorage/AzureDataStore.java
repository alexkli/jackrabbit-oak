/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.jackrabbit.oak.blob.cloud.azure.blobstorage;

import com.sun.istack.internal.Nullable;
import org.apache.jackrabbit.core.data.DataIdentifier;
import org.apache.jackrabbit.oak.plugins.blob.AbstractSharedCachingDataStore;
import org.apache.jackrabbit.oak.spi.blob.AbstractSharedBackend;
import org.apache.jackrabbit.oak.spi.blob.SharedBackend;
import org.apache.jackrabbit.oak.spi.blob.URLReadableDataStore;

import java.net.URL;
import java.util.Properties;

public class AzureDataStore extends AbstractSharedCachingDataStore implements URLReadableDataStore {

    private int minRecordLength = 16*1024;

    protected Properties properties;

    private AzureBlobStoreBackend azureBlobStoreBackend;

    @Override
    protected AbstractSharedBackend createBackend() {
        azureBlobStoreBackend = new AzureBlobStoreBackend();
        if (null != properties) {
            azureBlobStoreBackend.setProperties(properties);
        }
        return azureBlobStoreBackend;
    }

    public void setProperties(final Properties properties) {
        this.properties = properties;
    }

    public SharedBackend getBackend() {
        return backend;
    }

    @Override
    public int getMinRecordLength() {
        return minRecordLength;
    }

    public void setMinRecordLength(int minRecordLength) {
        this.minRecordLength = minRecordLength;
    }

    @Override
    public void setURLReadableBinaryExpirySeconds(int seconds) {
        if (null != azureBlobStoreBackend) {
            azureBlobStoreBackend.setURLReadableBinaryExpirySeconds(seconds);
        }
    }

    @Override
    public void setURLReadableBinaryURLCacheSize(int maxSize) {
        azureBlobStoreBackend.setURLReadableBinaryURLCacheSize(maxSize);
    }

    @Nullable
    @Override
    public URL getReadURL(DataIdentifier identifier) {
        if (null != azureBlobStoreBackend) {
            return azureBlobStoreBackend.createPresignedGetURL(identifier);
        }
        return null;
    }
}
