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

import com.google.common.base.Strings;
import com.sun.istack.internal.Nullable;
import org.apache.jackrabbit.core.data.DataIdentifier;
import org.apache.jackrabbit.core.data.DataRecord;
import org.apache.jackrabbit.core.data.DataStoreException;
import org.apache.jackrabbit.oak.plugins.blob.AbstractSharedCachingDataStore;
import org.apache.jackrabbit.oak.spi.blob.AbstractSharedBackend;
import org.apache.jackrabbit.oak.spi.blob.DirectBinaryAccessException;
import org.apache.jackrabbit.oak.spi.blob.SharedBackend;
import org.apache.jackrabbit.oak.spi.blob.URLReadableDataStore;
import org.apache.jackrabbit.oak.spi.blob.URLWritableDataStore;
import org.apache.jackrabbit.oak.spi.blob.URLWritableDataStoreUploadContext;

import java.net.URL;
import java.util.Properties;

public class AzureDataStore extends AbstractSharedCachingDataStore implements URLReadableDataStore, URLWritableDataStore {
    private int minRecordLength = 16*1024;

    /**
     * The minimum size of a file in order to do multi-part upload.
     */
    static final int minPartSize = AzureBlobStoreBackend.MIN_MULTIPART_UPLOAD_PART_SIZE;

    /**
     * The maximum size of a multi-part upload part (Azure limitation).
     */
    static final int maxPartSize = AzureBlobStoreBackend.MAX_MULTIPART_UPLOAD_PART_SIZE;

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

    @Override
    public void setURLWritableBinaryExpirySeconds(int seconds) {
        if (null != azureBlobStoreBackend) {
            azureBlobStoreBackend.setURLWritableBinaryExpirySeconds(seconds);
        }
    }

    @Override
    public void setURLBinaryTransferAcceleration(boolean enabled) {
        // NOOP - not a feature of Azure Blob Storage
    }

    @Override
    public URLWritableDataStoreUploadContext initDirectUpload(long maxUploadSizeInBytes, int maxNumberOfURLs) throws DirectBinaryAccessException {
        if (0L >= maxUploadSizeInBytes) {
            throw new DirectBinaryAccessException("maxUploadSizeInBytes must be > 0");
        }
        else if (0L >= maxNumberOfURLs) {
            throw new DirectBinaryAccessException("maxNumberOfURLs must be > 0");
        }
        if (azureBlobStoreBackend != null) {
            return azureBlobStoreBackend.initDirectUpload(maxUploadSizeInBytes, maxNumberOfURLs);
        }

        return null;
    }

    @Nullable
    @Override
    public DataRecord completeDirectUpload(String uploadToken) throws DirectBinaryAccessException, DataStoreException {
        if (Strings.isNullOrEmpty(uploadToken)) {
            throw new IllegalArgumentException("uploadToken required");
        }

        if (azureBlobStoreBackend != null) {
            return azureBlobStoreBackend.completeDirectUpload(uploadToken);
        }

        return null;
    }
}
