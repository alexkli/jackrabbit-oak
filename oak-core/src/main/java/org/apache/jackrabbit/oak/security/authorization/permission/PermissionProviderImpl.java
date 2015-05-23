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
package org.apache.jackrabbit.oak.security.authorization.permission;

import java.security.Principal;
import java.util.Collections;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.commons.PathUtils;
import org.apache.jackrabbit.oak.plugins.tree.RootFactory;
import org.apache.jackrabbit.oak.plugins.tree.TreeLocation;
import org.apache.jackrabbit.oak.plugins.tree.TreeType;
import org.apache.jackrabbit.oak.plugins.version.VersionConstants;
import org.apache.jackrabbit.oak.spi.security.ConfigurationParameters;
import org.apache.jackrabbit.oak.spi.security.Context;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.AccessControlConstants;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.AggregatedPermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionConstants;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.Permissions;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.RepositoryPermission;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.TreePermission;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeBits;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeBitsProvider;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.jackrabbit.oak.spi.state.NodeState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PermissionProviderImpl implements PermissionProvider, AccessControlConstants, PermissionConstants, AggregatedPermissionProvider {

    private final Logger log = LoggerFactory.getLogger("oak.security.access");

    private String user;

    private final Root root;

    private final String workspaceName;

    private final Set<Principal> principals;

    private final RestrictionProvider restrictionProvider;

    private final ConfigurationParameters options;

    private final Context ctx;

    private CompiledPermissions compiledPermissions;

    private Root immutableRoot;

    public PermissionProviderImpl(@Nonnull Root root, @Nonnull String workspaceName,
                                  @Nonnull Set<Principal> principals,
                                  @Nonnull RestrictionProvider restrictionProvider,
                                  @Nonnull ConfigurationParameters options,
                                  @Nonnull Context ctx) {
        this.root = root;
        this.workspaceName = workspaceName;
        this.principals = principals;
        this.restrictionProvider = restrictionProvider;
        this.options = options;
        this.ctx = ctx;

        immutableRoot = RootFactory.createReadOnlyRoot(root);

        try {
            user = root.getContentSession().getAuthInfo().getUserID();
        } catch (Exception e) {
            StringBuilder builder = new StringBuilder();
            final Iterator<Principal> principalsIter = principals.iterator();
            while (principalsIter.hasNext()) {
                builder.append(principalsIter.next().getName());
                if (principalsIter.hasNext()) {
                    builder.append(",");
                }
            }
            user = builder.toString();
        }
    }

    @Override
    public void refresh() {
        immutableRoot = RootFactory.createReadOnlyRoot(root);
        getCompiledPermissions().refresh(immutableRoot, workspaceName);
    }

    @Nonnull
    @Override
    public Set<String> getPrivileges(@Nullable Tree tree) {
        final Set<String> privileges = getCompiledPermissions().getPrivileges(PermissionUtil.getImmutableTree(tree, immutableRoot));
        if (log.isTraceEnabled()) {
            logAccess(tree == null ? "<null>" : tree.getPath(), AccessResult.OTHER, "getting privileges: " + join(toArray(privileges), ","));
        }
        return privileges;
    }

    @Override
    public boolean hasPrivileges(@Nullable Tree tree, @Nonnull String... privilegeNames) {
        final boolean isGranted = getCompiledPermissions().hasPrivileges(PermissionUtil.getImmutableTree(tree, immutableRoot), privilegeNames);
        if (log.isTraceEnabled()) {
            logAccess(tree == null ? "<null>" : tree.getPath(), isGranted, privilegeNames);
        }
        return isGranted;
    }

    @Nonnull
    @Override
    public RepositoryPermission getRepositoryPermission() {
        if (log.isTraceEnabled()) {
            logAccess("", AccessResult.OTHER, "<repository permissions>");
        }
        return getCompiledPermissions().getRepositoryPermission();
    }

    @Nonnull
    @Override
    public TreePermission getTreePermission(@Nonnull Tree tree, @Nonnull TreePermission parentPermission) {
        final TreePermission treePermission = getCompiledPermissions().getTreePermission(PermissionUtil.getImmutableTree(tree, immutableRoot), parentPermission);
        if (log.isTraceEnabled()) {
            return new LoggingTreePermission(treePermission, tree.getPath());
        }
        return treePermission;
    }

    @Override
    public boolean isGranted(@Nonnull Tree tree, @Nullable PropertyState property, long permissions) {
        final boolean isGranted = getCompiledPermissions().isGranted(PermissionUtil.getImmutableTree(tree, immutableRoot), property, permissions);
        if (log.isTraceEnabled()) {
            String path = property == null ? tree.getPath() : PathUtils.concat(tree.getPath(), property.getName());
            logAccess(path, isGranted, getPermissionNames(permissions));
        }
        return isGranted;
    }

    @Override
    public boolean isGranted(@Nonnull String oakPath, @Nonnull String jcrActions) {
        TreeLocation location = TreeLocation.create(immutableRoot, oakPath);
        boolean isAcContent = ctx.definesLocation(location);
        long permissions = Permissions.getPermissions(jcrActions, location, isAcContent);

        final boolean isGranted = isGranted(location, oakPath, permissions);
        if (log.isTraceEnabled()) {
            logAccess(oakPath, isGranted, jcrActions);
        }
        return isGranted;
    }

    //---------------------------------------< AggregatedPermissionProvider >---
    @Nonnull
    @Override
    public PrivilegeBits supportedPrivileges(@Nullable Tree tree, @Nullable PrivilegeBits privilegeBits) {
        return (privilegeBits != null) ? privilegeBits : new PrivilegeBitsProvider(immutableRoot).getBits(PrivilegeConstants.JCR_ALL);
    }

    @Override
    public long supportedPermissions(@Nullable Tree tree, @Nullable PropertyState property, long permissions) {
        return permissions;
    }

    @Override
    public long supportedPermissions(@Nonnull TreeLocation location, long permissions) {
        return permissions;
    }

    @Override
    public long supportedPermissions(@Nonnull TreePermission treePermission, @Nullable PropertyState property, long permissions) {
        return permissions;
    }

    @Override
    public boolean isGranted(@Nonnull TreeLocation location, long permissions) {
        return isGranted(location, location.getPath(), permissions);
    }

    @Nonnull
    @Override
    public TreePermission getTreePermission(@Nonnull Tree tree, @Nonnull TreeType type, @Nonnull TreePermission parentPermission) {
        return getCompiledPermissions().getTreePermission(PermissionUtil.getImmutableTree(tree, immutableRoot), type, parentPermission);
    }

    //--------------------------------------------------------------------------

    private enum AccessResult {
        ALLOWED("ALLOWED"),
        DENIED ("DENIED "),
        OTHER  ("OTHER  ");

        private final String text;

        AccessResult(String text) {
            this.text = text;
        }

        @Override
        public String toString() {
            return text;
        }
    }

    private void logAccess(String path, boolean isGranted, String... permissions) {
        logAccess(path, isGranted ? AccessResult.ALLOWED : AccessResult.DENIED, permissions);
    }

    private void logAccess(String path, AccessResult isGranted, String... permissions) {
        log.trace(
            "[{}] {} {} [{}]",
            user,
            isGranted.toString(),
            path,
            join(permissions, ",")
        );
    }

    private String join(String[] array, String delimiter) {
        if (array == null) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < array.length; i++) {
            builder.append(array[i]);
            if (i < array.length - 1) {
                builder.append(delimiter);
            }
        }
        return builder.toString();
    }

    private String[] toArray(Collection<String> strings) {
        return strings.toArray(new String[strings.size()]);
    }

    private String[] getPermissionNames(long permissions) {
        return toArray(Permissions.getNames(permissions));
    }

    private class LoggingTreePermission implements TreePermission {

        private TreePermission original;

        private String path;

        public LoggingTreePermission(TreePermission original, String path) {
            this.original = original;
            this.path = path;
        }

        @Nonnull
        @Override
        public TreePermission getChildPermission(@Nonnull String childName, @Nonnull NodeState childState) {
            return new LoggingTreePermission(original.getChildPermission(childName, childState), PathUtils.concat(path, childName));
        }

        @Override
        public boolean canRead() {
            final boolean canRead = original.canRead();
            if (log.isTraceEnabled()) {
                logAccess(path, canRead, "read");
            }
            return canRead;
        }

        @Override
        public boolean canRead(@Nonnull PropertyState property) {
            final boolean canRead = original.canRead(property);
            if (log.isTraceEnabled()) {
                logAccess(PathUtils.concat(path, property.getName()), canRead, "read property");
            }
            return canRead;
        }

        @Override
        public boolean canReadAll() {
            final boolean canReadAll = original.canReadAll();
            if (log.isTraceEnabled()) {
                logAccess(path, canReadAll, "read all");
            }
            return canReadAll;
        }

        @Override
        public boolean canReadProperties() {
            final boolean canReadProperties = original.canReadProperties();
            if (log.isTraceEnabled()) {
                logAccess(path, canReadProperties, "read properties");
            }
            return canReadProperties;
        }

        @Override
        public boolean isGranted(long permissions) {
            final boolean isGranted = original.isGranted(permissions);
            if (log.isTraceEnabled()) {
                logAccess(path, isGranted, getPermissionNames(permissions));
            }
            return isGranted;
        }

        @Override
        public boolean isGranted(long permissions, @Nonnull PropertyState property) {
            final boolean isGranted = original.isGranted(permissions, property);
            if (log.isTraceEnabled()) {
                logAccess(PathUtils.concat(path, property.getName()), isGranted, getPermissionNames(permissions));
            }
            return isGranted;
        }
    }

    private CompiledPermissions getCompiledPermissions() {
        CompiledPermissions cp = compiledPermissions;
        if (cp == null) {
            if (PermissionUtil.isAdminOrSystem(principals, options)) {
                cp = AllPermissions.getInstance();
            } else {
                cp = CompiledPermissionImpl.create(immutableRoot, workspaceName, principals, restrictionProvider, options, ctx);
            }
            compiledPermissions = cp;
        }
        return cp;
    }

    private static boolean isVersionStorePath(@Nonnull String oakPath) {
        return oakPath.startsWith(VersionConstants.VERSION_STORE_PATH);
    }

    private boolean isGranted(@Nonnull TreeLocation location, @Nonnull String oakPath, long permissions) {
        boolean isGranted = false;
        PropertyState property = location.getProperty();
        Tree tree = (property == null) ? location.getTree() : location.getParent().getTree();
        if (tree != null) {
            isGranted = isGranted(tree, property, permissions);
        } else if (!isVersionStorePath(location.getPath())) {
            isGranted = getCompiledPermissions().isGranted(oakPath, permissions);
        }
        return isGranted;
    }
}
