/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.jackrabbit.oak.blob.cloud.s3;

import static com.google.common.collect.Iterables.filter;
import static java.lang.Thread.currentThread;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Queue;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.annotation.Nonnull;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.HttpMethod;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.S3ClientOptions;
import com.amazonaws.services.s3.model.*;
import com.amazonaws.services.s3.transfer.Copy;
import com.amazonaws.services.s3.transfer.TransferManager;
import com.amazonaws.services.s3.transfer.Upload;
import com.amazonaws.util.StringUtils;
import com.google.common.base.Function;
import com.google.common.base.Predicate;
import com.google.common.base.Strings;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.AbstractIterator;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.NullInputStream;
import org.apache.jackrabbit.core.data.DataIdentifier;
import org.apache.jackrabbit.core.data.DataRecord;
import org.apache.jackrabbit.core.data.DataStoreException;
import org.apache.jackrabbit.core.data.util.NamedThreadFactory;
import org.apache.jackrabbit.oak.plugins.blob.datastore.directaccess.DataRecordDirectUpload;
import org.apache.jackrabbit.oak.plugins.blob.datastore.directaccess.DataRecordDirectUploadException;
import org.apache.jackrabbit.oak.plugins.blob.datastore.directaccess.DataRecordDirectUploadToken;
import org.apache.jackrabbit.oak.spi.blob.AbstractDataRecord;
import org.apache.jackrabbit.oak.spi.blob.AbstractSharedBackend;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A data store backend that stores data on Amazon S3.
 */
public class S3Backend extends AbstractSharedBackend {

    /**
     * Logger instance.
     */
    private static final Logger LOG = LoggerFactory.getLogger(S3Backend.class);

    private static final String KEY_PREFIX = "dataStore_";

    private static final String META_KEY_PREFIX = "META/";

    private static final String REF_KEY = "reference.key";

    private static final int MAX_UNIQUE_RECORD_TRIES = 10;

    static final String PART_NUMBER = "partNumber";
    static final String UPLOAD_ID = "uploadId";

    private static final int ONE_MB = 1024*1024;
    static final long MIN_MULTIPART_UPLOAD_PART_SIZE = 1024 * 1024 * 10; // 10MB
    static final long MAX_MULTIPART_UPLOAD_PART_SIZE = 1024 * 1024 * 256; // 256MB
    static final long MAX_SINGLE_PUT_UPLOAD_SIZE = 1024L * 1024L * 1024L * 5L; // 5GB, AWS limitation
    static final long MAX_BINARY_UPLOAD_SIZE = 1024L * 1024L * 1024L * 1024L * 5L; // 5TB, AWS limitation
    private static final int MAX_ALLOWABLE_UPLOAD_URIS = 10000; // AWS limitation

    private AmazonS3Client s3service;

    // needed only in case of transfer acceleration is enabled for presigned URIs
    private AmazonS3Client s3PresignService;

    private String bucket;

    private byte[] secret;

    private TransferManager tmx;

    private Properties properties;

    private Date startTime;

    private S3RequestDecorator s3ReqDecorator;

    private Cache<DataIdentifier, URI> httpDownloadURICache;

    // 0 = off by default
    private int httpUploadURIExpirySeconds = 0;
    private int httpDownloadURIExpirySeconds = 0;

    public void init() throws DataStoreException {
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();

        try {
            startTime = new Date();
            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());

            LOG.debug("init");

            s3ReqDecorator = new S3RequestDecorator(properties);
            s3service = Utils.openService(properties);
            s3PresignService = s3service;

            if (bucket == null || "".equals(bucket.trim())) {
                bucket = properties.getProperty(S3Constants.S3_BUCKET);
                // Alternately check if the 'container' property is set
                if (Strings.isNullOrEmpty(bucket)) {
                    bucket = properties.getProperty(S3Constants.S3_CONTAINER);
                }
            }
            String region = properties.getProperty(S3Constants.S3_REGION);
            Region s3Region;
            if (StringUtils.isNullOrEmpty(region)) {
                com.amazonaws.regions.Region ec2Region = Regions.getCurrentRegion();
                if (ec2Region != null) {
                    s3Region = Region.fromValue(ec2Region.getName());
                } else {
                    throw new AmazonClientException(
                            "parameter ["
                                    + S3Constants.S3_REGION
                                    + "] not configured and cannot be derived from environment");
                }
            } else {
                if (Utils.DEFAULT_AWS_BUCKET_REGION.equals(region)) {
                    s3Region = Region.US_Standard;
                } else if (Region.EU_Ireland.toString().equals(region)) {
                    s3Region = Region.EU_Ireland;
                } else {
                    s3Region = Region.fromValue(region);
                }
            }

            if (!s3service.doesBucketExist(bucket)) {
                s3service.createBucket(bucket, s3Region);
                LOG.info("Created bucket [{}] in [{}] ", bucket, region);
            } else {
                LOG.info("Using bucket [{}] in [{}] ", bucket, region);
            }

            int writeThreads = 10;
            String writeThreadsStr = properties.getProperty(S3Constants.S3_WRITE_THREADS);
            if (writeThreadsStr != null) {
                writeThreads = Integer.parseInt(writeThreadsStr);
            }
            LOG.info("Using thread pool of [{}] threads in S3 transfer manager.", writeThreads);
            tmx = new TransferManager(s3service, Executors.newFixedThreadPool(writeThreads,
                new NamedThreadFactory("s3-transfer-manager-worker")));

            String renameKeyProp = properties.getProperty(S3Constants.S3_RENAME_KEYS);
            boolean renameKeyBool = (renameKeyProp == null || "".equals(renameKeyProp))
                    ? false
                    : Boolean.parseBoolean(renameKeyProp);
            LOG.info("Rename keys [{}]", renameKeyBool);
            if (renameKeyBool) {
                renameKeys();
            }

            // settings around pre-signing

            String putExpiry = properties.getProperty(S3Constants.PRESIGNED_PUT_EXPIRY_SEC);
            if (putExpiry != null) {
                setHttpUploadURIExpirySeconds(Integer.parseInt(putExpiry));
            }

            String getExpiry = properties.getProperty(S3Constants.PRESIGNED_GET_EXPIRY_SEC);
            if (getExpiry != null) {
                final int getExpirySeconds = Integer.parseInt(getExpiry);
                setHttpDownloadURIExpirySeconds(getExpirySeconds);

                int cacheMaxSize = 0; // off by default
                String cacheMaxSizeStr = properties.getProperty(S3Constants.PRESIGNED_GET_URI_CACHE_MAX_SIZE);
                if (cacheMaxSizeStr != null) {
                    cacheMaxSize = Integer.parseInt(cacheMaxSizeStr);
                }

                setHttpDownloadURICacheSize(cacheMaxSize);
            }

            String enablePresignedAccelerationStr = properties.getProperty(S3Constants.PRESIGNED_URI_ENABLE_ACCELERATION);
            setBinaryTransferAccelerationEnabled(enablePresignedAccelerationStr != null && "true".equals(enablePresignedAccelerationStr));

            LOG.debug("S3 Backend initialized in [{}] ms",
                +(System.currentTimeMillis() - startTime.getTime()));
        } catch (Exception e) {
            LOG.error("Error ", e);
            Map<String, Object> filteredMap = Maps.newHashMap();
            if (properties != null) {
                filteredMap = Maps.filterKeys(Utils.asMap(properties), new Predicate<String>() {
                    @Override public boolean apply(String input) {
                        return !input.equals(S3Constants.ACCESS_KEY) &&
                            !input.equals(S3Constants.SECRET_KEY);
                    }
                });
            }
            throw new DataStoreException("Could not initialize S3 from " + filteredMap, e);
        } finally {
            if (contextClassLoader != null) {
                Thread.currentThread().setContextClassLoader(contextClassLoader);
            }
        }
    }

    public void setBinaryTransferAccelerationEnabled(boolean enabled) {
        if (enabled) {
            // verify acceleration is enabled on the bucket
            BucketAccelerateConfiguration accelerateConfig = s3service.getBucketAccelerateConfiguration(new GetBucketAccelerateConfigurationRequest(bucket));
            if (accelerateConfig.isAccelerateEnabled()) {
                // If transfer acceleration is enabled for presigned URIs, we need a separate AmazonS3Client
                // instance with the acceleration mode enabled, because we don't want the requests from the
                // data store itself to S3 to use acceleration
                s3PresignService = Utils.openService(properties);
                s3PresignService.setS3ClientOptions(S3ClientOptions.builder().setAccelerateModeEnabled(true).build());
                LOG.info("S3 Transfer Acceleration enabled for presigned URIs.");

            } else {
                LOG.warn("S3 Transfer Acceleration is not enabled on the bucket {}. Will create normal, non-accelerated presigned URIs.",
                    bucket, S3Constants.PRESIGNED_URI_ENABLE_ACCELERATION);
            }
        } else {
            s3PresignService = s3service;
        }
    }

    /**
     * It uploads file to Amazon S3. If file size is greater than 5MB, this
     * method uses parallel concurrent connections to upload.
     */
    @Override
    public void write(DataIdentifier identifier, File file)
        throws DataStoreException {
        String key = getKeyName(identifier);
        ObjectMetadata objectMetaData = null;
        long start = System.currentTimeMillis();
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(
                getClass().getClassLoader());
            // check if the same record already exists
            try {
                objectMetaData = s3service.getObjectMetadata(bucket, key);
            } catch (AmazonServiceException ase) {
                if (!(ase.getStatusCode() == 404 || ase.getStatusCode() == 403)) {
                    throw ase;
                }
            }
            if (objectMetaData != null) {
                long l = objectMetaData.getContentLength();
                if (l != file.length()) {
                    throw new DataStoreException("Collision: " + key
                        + " new length: " + file.length() + " old length: " + l);
                }
                LOG.debug("[{}]'s exists, lastmodified = [{}]", key,
                    objectMetaData.getLastModified().getTime());
                CopyObjectRequest copReq = new CopyObjectRequest(bucket, key,
                    bucket, key);
                copReq.setNewObjectMetadata(objectMetaData);
                Copy copy = tmx.copy(s3ReqDecorator.decorate(copReq));
                try {
                    copy.waitForCopyResult();
                    LOG.debug("lastModified of [{}] updated successfully.", identifier);
                }catch (Exception e2) {
                    throw new DataStoreException("Could not upload " + key, e2);
                }
            }

            if (objectMetaData == null) {
                try {
                    // start multipart parallel upload using amazon sdk
                    Upload up = tmx.upload(s3ReqDecorator.decorate(new PutObjectRequest(
                        bucket, key, file)));
                    // wait for upload to finish
                    up.waitForUploadResult();
                    LOG.debug("synchronous upload to identifier [{}] completed.", identifier);
                } catch (Exception e2 ) {
                    throw new DataStoreException("Could not upload " + key, e2);
                }
            }
        } finally {
            if (contextClassLoader != null) {
                Thread.currentThread().setContextClassLoader(contextClassLoader);
            }
        }
        LOG.debug("write of [{}], length=[{}], in [{}]ms",
            identifier, file.length(), (System.currentTimeMillis() - start));
    }

    /**
     * Check if record identified by identifier exists in Amazon S3.
     */
    @Override
    public boolean exists(DataIdentifier identifier) throws DataStoreException {
        long start = System.currentTimeMillis();
        String key = getKeyName(identifier);
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
            ObjectMetadata objectMetaData = s3service.getObjectMetadata(bucket,
                key);
            if (objectMetaData != null) {
                LOG.trace("exists [{}]: [true] took [{}] ms.",
                    identifier, (System.currentTimeMillis() - start) );
                return true;
            }
            return false;
        } catch (AmazonServiceException e) {
            if (e.getStatusCode() == 404 || e.getStatusCode() == 403) {
                LOG.debug("exists [{}]: [false] took [{}] ms.",
                    identifier, (System.currentTimeMillis() - start) );
                return false;
            }
            throw new DataStoreException(
                "Error occured to getObjectMetadata for key [" + identifier.toString() + "]", e);
        } finally {
            if (contextClassLoader != null) {
                Thread.currentThread().setContextClassLoader(contextClassLoader);
            }
        }
    }

    @Override
    public InputStream read(DataIdentifier identifier)
            throws DataStoreException {
        long start = System.currentTimeMillis();
        String key = getKeyName(identifier);
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
            S3Object object = s3service.getObject(bucket, key);
            InputStream in = object.getObjectContent();
            LOG.debug("[{}] read took [{}]ms", identifier, (System.currentTimeMillis() - start));
            if (LOG.isDebugEnabled()) {
                LOG.debug("binary downloaded from S3: " + identifier, new Exception());
            }
            return in;
        } catch (AmazonServiceException e) {
            throw new DataStoreException("Object not found: " + key, e);
        } finally {
            if (contextClassLoader != null) {
                Thread.currentThread().setContextClassLoader(contextClassLoader);
            }
        }
    }

    @Override
    public Iterator<DataIdentifier> getAllIdentifiers()
            throws DataStoreException {
        return new RecordsIterator<DataIdentifier>(
            new Function<S3ObjectSummary, DataIdentifier>() {
                @Override
                public DataIdentifier apply(S3ObjectSummary input) {
                    return new DataIdentifier(getIdentifierName(input.getKey()));
                }
        });
    }

    @Override
    public void deleteRecord(DataIdentifier identifier)
            throws DataStoreException {
        long start = System.currentTimeMillis();
        String key = getKeyName(identifier);
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(
                getClass().getClassLoader());
            s3service.deleteObject(bucket, key);
            LOG.debug("Identifier [{}] deleted. It took [{}]ms.", new Object[] {
                identifier, (System.currentTimeMillis() - start) });
        } catch (AmazonServiceException e) {
            throw new DataStoreException(
                "Could not delete dataIdentifier " + identifier, e);
        } finally {
            if (contextClassLoader != null) {
                Thread.currentThread().setContextClassLoader(contextClassLoader);
            }
        }
    }

    @Override
    public void close() {
        // backend is closing. abort all mulitpart uploads from start.
        if(s3service.doesBucketExist(bucket)) {
            tmx.abortMultipartUploads(bucket, startTime);
        }
        tmx.shutdownNow();
        s3service.shutdown();
        LOG.info("S3Backend closed.");
    }

    public String getBucket() {
        return bucket;
    }

    public void setBucket(String bucket) {
        this.bucket = bucket;
    }

    /**
     * Properties used to configure the backend. If provided explicitly
     * before init is invoked then these take precedence
     *
     * @param properties  to configure S3Backend
     */
    public void setProperties(Properties properties) {
        this.properties = properties;
    }

    @Override
    public void addMetadataRecord(final InputStream input, final String name) throws DataStoreException {
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();

        try {
            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());

            Upload upload = tmx.upload(s3ReqDecorator
                .decorate(new PutObjectRequest(bucket, addMetaKeyPrefix(name), input, new ObjectMetadata())));
            upload.waitForUploadResult();
        } catch (InterruptedException e) {
            LOG.error("Error in uploading", e);
            throw new DataStoreException("Error in uploading", e);
        } finally {
            if (contextClassLoader != null) {
                Thread.currentThread().setContextClassLoader(contextClassLoader);
            }
        }
    }

    @Override
    public void addMetadataRecord(File input, String name) throws DataStoreException {
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());

            Upload upload = tmx.upload(s3ReqDecorator
                .decorate(new PutObjectRequest(bucket, addMetaKeyPrefix(name), input)));
            upload.waitForUploadResult();
        } catch (InterruptedException e) {
            LOG.error("Exception in uploading metadata file {}", new Object[] {input, e});
            throw new DataStoreException("Error in uploading metadata file", e);
        } finally {
            if (contextClassLoader != null) {
                Thread.currentThread().setContextClassLoader(contextClassLoader);
            }
        }
    }

    @Override
    public DataRecord getMetadataRecord(String name) {
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(
                getClass().getClassLoader());
            ObjectMetadata meta = s3service.getObjectMetadata(bucket, addMetaKeyPrefix(name));
            return new S3DataRecord(this, s3service, bucket, new DataIdentifier(name),
                meta.getLastModified().getTime(), meta.getContentLength(), true);
        } finally {
            if (contextClassLoader != null) {
                Thread.currentThread().setContextClassLoader(contextClassLoader);
            }
        }
    }

    @Override
    public List<DataRecord> getAllMetadataRecords(String prefix) {
        List<DataRecord> metadataList = new ArrayList<DataRecord>();
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(
                getClass().getClassLoader());
            ListObjectsRequest listObjectsRequest =
                new ListObjectsRequest().withBucketName(bucket).withPrefix(addMetaKeyPrefix(prefix));
            ObjectListing prevObjectListing = s3service.listObjects(listObjectsRequest);
            for (final S3ObjectSummary s3ObjSumm : prevObjectListing.getObjectSummaries()) {
                metadataList.add(new S3DataRecord(this, s3service, bucket,
                    new DataIdentifier(stripMetaKeyPrefix(s3ObjSumm.getKey())),
                    s3ObjSumm.getLastModified().getTime(), s3ObjSumm.getSize(), true));
            }
        } finally {
            if (contextClassLoader != null) {
                Thread.currentThread().setContextClassLoader(contextClassLoader);
            }
        }
        return metadataList;
    }

    @Override
    public boolean deleteMetadataRecord(String name) {
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(
                getClass().getClassLoader());
            s3service.deleteObject(bucket, addMetaKeyPrefix(name));
        } finally {
            if (contextClassLoader != null) {
                Thread.currentThread().setContextClassLoader(contextClassLoader);
            }
        }
        return true;
    }

    @Override
    public void deleteAllMetadataRecords(String prefix) {
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(
                getClass().getClassLoader());

            ListObjectsRequest listObjectsRequest =
                new ListObjectsRequest().withBucketName(bucket).withPrefix(addMetaKeyPrefix(prefix));
            ObjectListing metaList = s3service.listObjects(listObjectsRequest);
            List<DeleteObjectsRequest.KeyVersion> deleteList = new ArrayList<DeleteObjectsRequest.KeyVersion>();
            for (S3ObjectSummary s3ObjSumm : metaList.getObjectSummaries()) {
                deleteList.add(new DeleteObjectsRequest.KeyVersion(s3ObjSumm.getKey()));
            }
            if (deleteList.size() > 0) {
                DeleteObjectsRequest delObjsReq = new DeleteObjectsRequest(bucket);
                delObjsReq.setKeys(deleteList);
                s3service.deleteObjects(delObjsReq);
            }
        } finally {
            if (contextClassLoader != null) {
                Thread.currentThread().setContextClassLoader(contextClassLoader);
            }
        }
    }

    @Override
    public Iterator<DataRecord> getAllRecords() {
        final AbstractSharedBackend backend = this;
        return new RecordsIterator<DataRecord>(
            new Function<S3ObjectSummary, DataRecord>() {
                @Override
                public DataRecord apply(S3ObjectSummary input) {
                    return new S3DataRecord(backend, s3service, bucket,
                        new DataIdentifier(getIdentifierName(input.getKey())),
                        input.getLastModified().getTime(), input.getSize());
                }
            });
    }

    @Override
    public DataRecord getRecord(DataIdentifier identifier) throws DataStoreException {
        long start = System.currentTimeMillis();
        String key = getKeyName(identifier);
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());

            ObjectMetadata object = s3service.getObjectMetadata(bucket, key);
            S3DataRecord record = new S3DataRecord(this, s3service, bucket, identifier,
                object.getLastModified().getTime(), object.getContentLength());
            LOG.debug("Identifier [{}]'s getRecord = [{}] took [{}]ms.",
                identifier, record, (System.currentTimeMillis() - start));

            return record;
        } catch (AmazonServiceException e) {
            if (e.getStatusCode() == 404 || e.getStatusCode() == 403) {
                    LOG.info(
                        "getRecord:Identifier [{}] not found. Took [{}] ms.",
                        identifier, (System.currentTimeMillis() - start));
                }
            throw new DataStoreException(e);
        } finally {
            if (contextClassLoader != null) {
                Thread.currentThread().setContextClassLoader(contextClassLoader);
            }
        }
    }

    @Override
    public byte[] getOrCreateReferenceKey() throws DataStoreException {
        try {
            if (secret != null && secret.length != 0) {
                return secret;
            } else {
                byte[] key;
                // Try reading from the metadata folder if it exists
                if (metadataExists(REF_KEY)) {
                    key = readMetadataBytes(REF_KEY);
                } else {
                    // Create a new key and then retrieve it to use it
                    key = super.getOrCreateReferenceKey();
                    addMetadataRecord(new ByteArrayInputStream(key), REF_KEY);
                    key = readMetadataBytes(REF_KEY);
                }
                secret = key;
                return secret;
            }
        } catch (IOException e) {
            throw new DataStoreException("Unable to get or create key " + e);
        }
    }

    private byte[] readMetadataBytes(String name) throws IOException, DataStoreException {
        DataRecord rec = getMetadataRecord(name);
        InputStream stream = null;
        try {
            stream = rec.getStream();
            return IOUtils.toByteArray(stream);
        } finally {
            IOUtils.closeQuietly(stream);
        }
    }

    private boolean metadataExists(String name) {
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(
                getClass().getClassLoader());
            return s3service.doesObjectExist(bucket, addMetaKeyPrefix(name));
        } finally {
            if (contextClassLoader != null) {
                Thread.currentThread().setContextClassLoader(contextClassLoader);
            }
        }
    }

    public void setHttpUploadURIExpirySeconds(int seconds) {
        this.httpUploadURIExpirySeconds = seconds;
    }

    public DataIdentifier generateSafeRandomIdentifier()
            throws DataRecordDirectUploadException {
        // In case our random uuid generation fails and hits only existing keys
        // (however unlikely), try only a limited number of times to avoid
        // endless loop and throw instead.
        //
        // The odds of a UUID collision are about 1 in 2^-122, or approximately
        // 1 in 5 undecillion (5,000,000,000,000,000,000,000,000,000,000,000,000).
        // These odds are small, but still higher than a SHA-256 collision which
        // are about 1 in 4.3*10^-43, or approximately 1 in 4 tredecillion
        // (43,000,000,000,000,000,000,000,000,000,000,000,000,000,000) - or
        // in other words, a UUID collision is about 10,000,000 times more
        // likely.
        try {
            for (int i = 0; i < MAX_UNIQUE_RECORD_TRIES; i++) {
                // a random UUID instead of a content hash
                final String id = UUID.randomUUID().toString();

                final DataIdentifier identifier = new DataIdentifier(id);
                if (exists(identifier)) {
                    LOG.info("Newly generated random record id already exists as S3 key [try {} of {}]: {}", id, i, MAX_UNIQUE_RECORD_TRIES);
                    continue;
                }
                LOG.info("Created new unique record id: {}", id);
                return identifier;
            }
            throw new DataRecordDirectUploadException("Could not generate a new unique record id in " + MAX_UNIQUE_RECORD_TRIES + " tries");
        }
        catch (DataStoreException e) {
            throw new DataRecordDirectUploadException(e);
        }
    }

    public URI createPresignedPutURI(DataIdentifier identifier) {
        if (httpUploadURIExpirySeconds <= 0) {
            // feature disabled
            return null;
        }

        return createPresignedURI(identifier, HttpMethod.PUT, httpUploadURIExpirySeconds);
    }

    public void setHttpDownloadURIExpirySeconds(int seconds) {
        this.httpDownloadURIExpirySeconds = seconds;
    }

    public void setHttpDownloadURICacheSize(int maxSize) {
        // max size 0 or smaller is used to turn off the cache
        if (maxSize > 0) {
            LOG.info("presigned GET URI cache enabled, maxSize = {} items, expiry = {} seconds", maxSize, httpDownloadURIExpirySeconds / 2);
            httpDownloadURICache = CacheBuilder.newBuilder()
                    .maximumSize(maxSize)
                    // cache for half the expiry time of the URIs before giving out new ones
                    .expireAfterWrite(httpDownloadURIExpirySeconds / 2, TimeUnit.SECONDS)
                    .build();
        } else {
            LOG.info("presigned GET URI cache disabled");
            httpDownloadURICache = null;
        }
    }

    public URI createHttpDownloadURI(@Nonnull DataIdentifier identifier) {
        if (httpDownloadURIExpirySeconds <= 0) {
            // feature disabled
            return null;
        }

        URI uri = null;
        // if cache is enabled, check the cache
        if (httpDownloadURICache != null) {
            uri = httpDownloadURICache.getIfPresent(identifier);
        }
        if (uri == null) {
            uri = createPresignedURI(identifier, HttpMethod.GET, httpDownloadURIExpirySeconds);
            if (uri != null && httpDownloadURICache != null) {
                httpDownloadURICache.put(identifier, uri);
            }
        }
        return uri;
    }

    public DataRecordDirectUpload initiateHttpUpload(long maxUploadSizeInBytes, int maxNumberOfURIs)
            throws DataRecordDirectUploadException {
        List<URI> uploadPartURIs = Lists.newArrayList();
        long minPartSize = MIN_MULTIPART_UPLOAD_PART_SIZE;
        long maxPartSize = MAX_MULTIPART_UPLOAD_PART_SIZE;

        if (0L >= maxUploadSizeInBytes) {
            throw new IllegalArgumentException("maxUploadSizeInBytes must be > 0");
        }
        else if (0 == maxNumberOfURIs) {
            throw new IllegalArgumentException("maxNumberOfURIs must either be > 0 or -1");
        }
        else if (-1 > maxNumberOfURIs) {
            throw new IllegalArgumentException("maxNumberOfURIs must either be > 0 or -1");
        }
        else if (maxUploadSizeInBytes > MAX_SINGLE_PUT_UPLOAD_SIZE &&
                maxNumberOfURIs == 1) {
            throw new IllegalArgumentException(
                    String.format("Cannot do single-put upload with file size %d", maxUploadSizeInBytes)
            );
        }
        else if (maxUploadSizeInBytes > MAX_BINARY_UPLOAD_SIZE) {
            throw new IllegalArgumentException(
                    String.format("Cannot do upload with file size %d", maxUploadSizeInBytes)
            );
        }

        DataIdentifier newIdentifier = generateSafeRandomIdentifier();
        String blobId = getKeyName(newIdentifier);
        String uploadId = null;

        if (httpUploadURIExpirySeconds > 0) {
            if (maxNumberOfURIs == 1 ||
                    maxUploadSizeInBytes <= minPartSize) {
                // single put
                uploadPartURIs.add(createPresignedPutURI(newIdentifier));
            }
            else {
                // multi-part
                InitiateMultipartUploadRequest req = new InitiateMultipartUploadRequest(bucket, blobId);
                InitiateMultipartUploadResult res = s3service.initiateMultipartUpload(req);
                uploadId = res.getUploadId();

                long numParts = maxNumberOfURIs;
                if (maxNumberOfURIs > 1) {
                    long requestedPartSize = (long) Math.ceil(((double) maxUploadSizeInBytes) / ((double) maxNumberOfURIs));
                    if (requestedPartSize <= maxPartSize) {
                        numParts = Math.min(
                                maxNumberOfURIs,
                                Math.min(
                                        (long) Math.ceil(((double) maxUploadSizeInBytes) / ((double) minPartSize)),
                                        MAX_ALLOWABLE_UPLOAD_URIS
                                )
                        );
                    } else {
                        throw new IllegalArgumentException(
                                String.format("Cannot do multi-part upload with requested part size %d", requestedPartSize)
                        );
                    }
                }
                else {
                    long maximalNumParts = (long) Math.ceil(((double) maxUploadSizeInBytes) / ((double) MIN_MULTIPART_UPLOAD_PART_SIZE));
                    numParts = Math.min(maximalNumParts, MAX_ALLOWABLE_UPLOAD_URIS);
                }

                Map<String, String> presignedURIRequestParams = Maps.newHashMap();
                for (long blockId = 1; blockId <= numParts; ++blockId) {
                    presignedURIRequestParams.put("partNumber", String.valueOf(blockId));
                    presignedURIRequestParams.put("uploadId", uploadId);
                    uploadPartURIs.add(createPresignedURI(newIdentifier,
                            HttpMethod.PUT,
                            httpUploadURIExpirySeconds,
                            presignedURIRequestParams));
                }
            }
        }

        byte[] secret = null;
        try {
            secret = getOrCreateReferenceKey();
        }
        catch (DataStoreException e) {
            LOG.warn("Unable to obtain data store key");
        }

        String uploadToken = new DataRecordDirectUploadToken(blobId, uploadId).getEncodedToken(secret);

        return new DataRecordDirectUpload() {
            @Override
            public String getUploadToken() { return uploadToken; }

            @Override
            public long getMinPartSize() { return minPartSize; }

            @Override
            public long getMaxPartSize() { return maxPartSize; }

            @Override
            public Collection<URI> getUploadURIs() { return uploadPartURIs; }
        };
    }

    public DataRecord completeHttpUpload(@Nonnull String uploadTokenStr)
            throws DataRecordDirectUploadException, DataStoreException {

        if (Strings.isNullOrEmpty(uploadTokenStr)) {
            throw new IllegalArgumentException("uploadToken required");
        }

        DataRecordDirectUploadToken uploadToken = DataRecordDirectUploadToken.fromEncodedToken(uploadTokenStr, getOrCreateReferenceKey());
        String blobId = uploadToken.getBlobId();
        if (uploadToken.getUploadId().isPresent()) {
            // An existing upload ID means this is a multi-part upload
            String uploadId = uploadToken.getUploadId().get();
            ListPartsRequest listPartsRequest = new ListPartsRequest(bucket, blobId, uploadId);
            PartListing listing = s3service.listParts(listPartsRequest);
            List<PartETag> eTags = Lists.newArrayList();
            for (PartSummary partSummary : listing.getParts()) {
                PartETag eTag = new PartETag(partSummary.getPartNumber(), partSummary.getETag());
                eTags.add(eTag);
            }

            CompleteMultipartUploadRequest completeReq = new CompleteMultipartUploadRequest(
                    bucket,
                    blobId,
                    uploadId,
                    eTags
            );

            s3service.completeMultipartUpload(completeReq);
        }
        // else do nothing - single-put upload is already complete


        if (! s3service.doesObjectExist(bucket, blobId)) {
            throw new DataRecordDirectUploadException(
                    String.format("Unable to finalize direct write of binary %s", blobId)
            );
        }

        return getRecord(new DataIdentifier(getIdentifierName(blobId)));
    }

    private URI createPresignedURI(DataIdentifier identifier, HttpMethod method, int expirySeconds) {
        return createPresignedURI(identifier, method, expirySeconds, Maps.newHashMap());
    }

    private URI createPresignedURI(DataIdentifier identifier, HttpMethod method, int expirySeconds, Map<String, String> reqParams) {
        final String key = getKeyName(identifier);

        try {
            final Date expiration = new Date();
            expiration.setTime(expiration.getTime() + expirySeconds * 1000);

            GeneratePresignedUrlRequest request = new GeneratePresignedUrlRequest(bucket, key)
                    .withMethod(method)
                    .withExpiration(expiration);

            for (Map.Entry<String, String> e : reqParams.entrySet()) {
                request.addRequestParameter(e.getKey(), e.getValue());
            }

            URI uri = null;
            URL presignedURL = null;
            try {
                presignedURL = s3PresignService.generatePresignedUrl(request);
                uri = presignedURL.toURI();

                LOG.debug("Presigned {} URI for key {}: {}", method.name(), key, uri.toString());
            }
            catch (URISyntaxException e) {
                LOG.error("AWS request to create presigned S3 URI failed - could not convert '{}' to URI",
                        (null != presignedURL ? presignedURL.toString() : "")
                );
            }

            return uri;

        } catch (AmazonServiceException e) {
            LOG.error("AWS request to create presigned S3 {} URI failed. " +
                            "Key: {}, Error: {}, HTTP Code: {}, AWS Error Code: {}, Error Type: {}, Request ID: {}",
                    method.name(), key, e.getMessage(), e.getStatusCode(), e.getErrorCode(), e.getErrorType(), e.getRequestId());

            return null;
        }
    }

    /**
     * Returns an iterator over the S3 objects
     * @param <T>
     */
    class RecordsIterator<T> extends AbstractIterator<T> {
        ObjectListing prevObjectListing;
        Queue<S3ObjectSummary> queue;
        long size;
        Function<S3ObjectSummary, T> transformer;

        public RecordsIterator (Function<S3ObjectSummary, T> transformer) {
            queue = Lists.newLinkedList();
            this.transformer = transformer;
        }

        @Override
        protected T computeNext() {
            if (queue.isEmpty()) {
                loadBatch();
            }

            if (!queue.isEmpty()) {
                return transformer.apply(queue.remove());
            }

            return endOfData();
        }

        private boolean loadBatch() {
            ClassLoader contextClassLoader = currentThread().getContextClassLoader();
            long start = System.currentTimeMillis();
            try {
                currentThread().setContextClassLoader(getClass().getClassLoader());

                // initialize the listing the first time
                if (prevObjectListing == null) {
                    prevObjectListing = s3service.listObjects(bucket);
                } else if (prevObjectListing.isTruncated()) { //already initialized more objects available
                    prevObjectListing = s3service.listNextBatchOfObjects(prevObjectListing);
                } else { // no more available
                    return false;
                }

                List<S3ObjectSummary> listing = Lists.newArrayList(
                    filter(prevObjectListing.getObjectSummaries(),
                        new Predicate<S3ObjectSummary>() {
                            @Override
                            public boolean apply(S3ObjectSummary input) {
                                return !input.getKey().startsWith(META_KEY_PREFIX);
                            }
                        }));

                // After filtering no elements
                if (listing.isEmpty()) {
                    return false;
                }

                size += listing.size();
                queue.addAll(listing);

                LOG.info("Loaded batch of size [{}] in [{}] ms.",
                    listing.size(), (System.currentTimeMillis() - start));

                return true;
            } catch (AmazonServiceException e) {
                LOG.warn("Could not list objects", e);
            } finally {
                if (contextClassLoader != null) {
                    currentThread().setContextClassLoader(contextClassLoader);
                }
            }
            return false;
        }
    }

    private static String addMetaKeyPrefix(String key) {
        return META_KEY_PREFIX + key;
    }

    private static String stripMetaKeyPrefix(String name) {
        if (name.startsWith(META_KEY_PREFIX)) {
            return name.substring(META_KEY_PREFIX.length());
        }
        return name;
    }

    /**
     * S3DataRecord which lazily retrieves the input stream of the record.
     */
    static class S3DataRecord extends AbstractDataRecord {
        private AmazonS3Client s3service;
        private long length;
        private long lastModified;
        private String bucket;
        private boolean isMeta;

        public S3DataRecord(AbstractSharedBackend backend, AmazonS3Client s3service, String bucket,
            DataIdentifier key, long lastModified,
            long length) {
            this(backend, s3service, bucket, key, lastModified, length, false);
        }

        public S3DataRecord(AbstractSharedBackend backend, AmazonS3Client s3service, String bucket,
            DataIdentifier key, long lastModified,
            long length, boolean isMeta) {
            super(backend, key);
            this.s3service = s3service;
            this.lastModified = lastModified;
            this.length = length;
            this.bucket = bucket;
            this.isMeta = isMeta;
        }

        @Override
        public long getLength() throws DataStoreException {
            return length;
        }

        @Override
        public InputStream getStream() throws DataStoreException {
            String id = getKeyName(getIdentifier());
            if (isMeta) {
                id = addMetaKeyPrefix(getIdentifier().toString());
            }
            if (LOG.isDebugEnabled()) {
                // Log message, with exception so we can get a trace to see where the call
                // came from
                LOG.debug("binary downloaded from S3: " + getIdentifier(), new Exception());
            }
            return s3service.getObject(bucket, id).getObjectContent();
        }

        @Override
        public long getLastModified() {
            return lastModified;
        }

        @Override
        public String toString() {
            return "S3DataRecord{" +
                "identifier=" + getIdentifier() +
                ", length=" + length +
                ", lastModified=" + lastModified +
                ", bucket='" + bucket + '\'' +
                '}';
        }
    }

    /**
     * This method rename object keys in S3 concurrently. The number of
     * concurrent threads is defined by 'maxConnections' property in
     * aws.properties. As S3 doesn't have "move" command, this method simulate
     * move as copy object object to new key and then delete older key.
     */
    private void renameKeys() throws DataStoreException {
        long startTime = System.currentTimeMillis();
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        long count = 0;
        try {
            Thread.currentThread().setContextClassLoader(
                getClass().getClassLoader());
            ObjectListing prevObjectListing = s3service.listObjects(bucket);
            List<DeleteObjectsRequest.KeyVersion> deleteList = new ArrayList<DeleteObjectsRequest.KeyVersion>();
            int nThreads = Integer.parseInt(properties.getProperty("maxConnections"));
            ExecutorService executor = Executors.newFixedThreadPool(nThreads,
                new NamedThreadFactory("s3-object-rename-worker"));
            boolean taskAdded = false;
            while (true) {
                for (S3ObjectSummary s3ObjSumm : prevObjectListing.getObjectSummaries()) {
                    executor.execute(new KeyRenameThread(s3ObjSumm.getKey()));
                    taskAdded = true;
                    count++;
                    // delete the object if it follows old key name format
                    if( s3ObjSumm.getKey().startsWith(KEY_PREFIX)) {
                        deleteList.add(new DeleteObjectsRequest.KeyVersion(
                            s3ObjSumm.getKey()));
                    }
                }
                if (!prevObjectListing.isTruncated()) break;
                prevObjectListing = s3service.listNextBatchOfObjects(prevObjectListing);
            }
            // This will make the executor accept no new threads
            // and finish all existing threads in the queue
            executor.shutdown();

            try {
                // Wait until all threads are finish
                while (taskAdded
                    && !executor.awaitTermination(10, TimeUnit.SECONDS)) {
                    LOG.info("Rename S3 keys tasks timedout. Waiting again");
                }
            } catch (InterruptedException ie) {

            }
            LOG.info("Renamed [{}] keys, time taken [{}]sec", count,
                ((System.currentTimeMillis() - startTime) / 1000));
            // Delete older keys.
            if (deleteList.size() > 0) {
                DeleteObjectsRequest delObjsReq = new DeleteObjectsRequest(
                    bucket);
                int batchSize = 500, startIndex = 0, size = deleteList.size();
                int endIndex = batchSize < size ? batchSize : size;
                while (endIndex <= size) {
                    delObjsReq.setKeys(Collections.unmodifiableList(deleteList.subList(
                        startIndex, endIndex)));
                    DeleteObjectsResult dobjs = s3service.deleteObjects(delObjsReq);
                    LOG.info("Records[{}] deleted in datastore from index [{}] to [{}]",
                        dobjs.getDeletedObjects().size(), startIndex, (endIndex - 1));
                    if (endIndex == size) {
                        break;
                    } else {
                        startIndex = endIndex;
                        endIndex = (startIndex + batchSize) < size
                                ? (startIndex + batchSize)
                                : size;
                    }
                }
            }
        } finally {
            if (contextClassLoader != null) {
                Thread.currentThread().setContextClassLoader(contextClassLoader);
            }
        }
    }

    /**
     * The method convert old key format to new format. For e.g. this method
     * converts old key dataStore_004cb70c8f87d78f04da41e7547cb434094089ea to
     * 004c-b70c8f87d78f04da41e7547cb434094089ea.
     */
    private static String convertKey(String oldKey)
            throws IllegalArgumentException {
        if (!oldKey.startsWith(KEY_PREFIX)) {
            return oldKey;
        }
        String key = oldKey.substring(KEY_PREFIX.length());
        return key.substring(0, 4) + Utils.DASH + key.substring(4);
    }

    /**
     * Get key from data identifier. Object is stored with key in S3.
     */
    private static String getKeyName(DataIdentifier identifier) {
        String key = identifier.toString();
        return key.substring(0, 4) + Utils.DASH + key.substring(4);
    }

    /**
     * Get data identifier from key.
     */
    private static String getIdentifierName(String key) {
        if (!key.contains(Utils.DASH)) {
            return null;
        } else if (key.contains(META_KEY_PREFIX)) {
            return key;
        }
        return key.substring(0, 4) + key.substring(5);
    }


    /**
     * The class renames object key in S3 in a thread.
     */
    private class KeyRenameThread implements Runnable {

        private String oldKey;

        public void run() {
            ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
            try {
                Thread.currentThread().setContextClassLoader(
                    getClass().getClassLoader());
                String newS3Key = convertKey(oldKey);
                CopyObjectRequest copReq = new CopyObjectRequest(bucket,
                    oldKey, bucket, newS3Key);
                Copy copy = tmx.copy(s3ReqDecorator.decorate(copReq));
                try {
                    copy.waitForCopyResult();
                    LOG.debug("[{}] renamed to [{}] ", oldKey, newS3Key);
                } catch (InterruptedException ie) {
                    LOG.error(" Exception in renaming [{}] to [{}] ", ie, oldKey, newS3Key);
                }

            } finally {
                if (contextClassLoader != null) {
                    Thread.currentThread().setContextClassLoader(
                        contextClassLoader);
                }
            }
        }

        public KeyRenameThread(String oldKey) {
            this.oldKey = oldKey;
        }
    }

    private class EmptyRecord implements DataRecord {

        private final DataIdentifier identifier;

        public EmptyRecord(DataIdentifier identifier) {
            this.identifier = identifier;
        }

        @Override
        public DataIdentifier getIdentifier() {
            return identifier;
        }

        @Override
        public String getReference() {
            return null;
        }

        @Override
        public long getLength() throws DataStoreException {
            return 0;
        }

        @Override
        public InputStream getStream() throws DataStoreException {
            // return empty stream
            return new NullInputStream(0);
        }

        @Override
        public long getLastModified() {
            return 0;
        }

        public String toString() {
            return identifier.toString();
        }

        public boolean equals(Object object) {
            return (object instanceof DataRecord)
                && identifier.equals(((DataRecord) object).getIdentifier());
        }

        public int hashCode() {
            return identifier.hashCode();
        }
    }
}
