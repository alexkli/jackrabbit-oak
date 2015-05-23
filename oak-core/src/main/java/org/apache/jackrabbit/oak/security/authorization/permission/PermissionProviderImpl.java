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
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.jackrabbit.JcrConstants;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.commons.PathUtils;
import org.apache.jackrabbit.oak.plugins.tree.RootFactory;
import org.apache.jackrabbit.oak.plugins.tree.TreeLocation;
import org.apache.jackrabbit.oak.plugins.tree.impl.ImmutableTree;
import org.apache.jackrabbit.oak.plugins.version.VersionConstants;
import org.apache.jackrabbit.oak.spi.security.authorization.AuthorizationConfiguration;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.AccessControlConstants;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.AggregatedPermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionConstants;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.Permissions;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.RepositoryPermission;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.TreePermission;
import org.apache.jackrabbit.oak.spi.security.principal.AdminPrincipal;
import org.apache.jackrabbit.oak.spi.security.principal.SystemPrincipal;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeBits;
import org.apache.jackrabbit.oak.spi.state.NodeState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PermissionProviderImpl implements PermissionProvider, AccessControlConstants, PermissionConstants, AggregatedPermissionProvider {

    private final Logger log = LoggerFactory.getLogger("oak.security.access");

    private String user;

    private final Root root;

    private final String workspaceName;

    private final AuthorizationConfiguration acConfig;

    private final CompiledPermissions compiledPermissions;

    private Root immutableRoot;

    public PermissionProviderImpl(@Nonnull Root root, @Nonnull String workspaceName, @Nonnull Set<Principal> principals,
                                  @Nonnull AuthorizationConfiguration acConfig) {
        this.root = root;
        this.workspaceName = workspaceName;
        this.acConfig = acConfig;

        immutableRoot = RootFactory.createReadOnlyRoot(root);

        if (principals.contains(SystemPrincipal.INSTANCE) || isAdmin(principals)) {
            compiledPermissions = AllPermissions.getInstance();
        } else {
            compiledPermissions = CompiledPermissionImpl.create(immutableRoot, workspaceName, principals, acConfig);
        }

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
        compiledPermissions.refresh(immutableRoot, workspaceName);
    }

    @Nonnull
    @Override
    public Set<String> getPrivileges(@Nullable Tree tree) {
        final Set<String> privileges = compiledPermissions.getPrivileges(getImmutableTree(tree));
        if (log.isTraceEnabled()) {
            logAccess(tree == null ? "<null>" : tree.getPath(), AccessResult.OTHER, "getting privileges: " + join(toArray(privileges), ","));
        }
        return privileges;
    }

    @Override
    public boolean hasPrivileges(@Nullable Tree tree, @Nonnull String... privilegeNames) {
        final boolean isGranted = compiledPermissions.hasPrivileges(getImmutableTree(tree), privilegeNames);
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
        return compiledPermissions.getRepositoryPermission();
    }

    @Nonnull
    @Override
    public TreePermission getTreePermission(@Nonnull Tree tree, @Nonnull TreePermission parentPermission) {
        final TreePermission treePermission = compiledPermissions.getTreePermission(getImmutableTree(tree), parentPermission);
        if (log.isTraceEnabled()) {
            return new LoggingTreePermission(treePermission, tree.getPath());
        }
        return treePermission;
    }

    @Override
    public boolean isGranted(@Nonnull Tree tree, @Nullable PropertyState property, long permissions) {
        final boolean isGranted = compiledPermissions.isGranted(getImmutableTree(tree), property, permissions);
        if (log.isTraceEnabled()) {
            String path = property == null ? tree.getPath() : PathUtils.concat(tree.getPath(), property.getName());
            logAccess(path, isGranted, getPermissionNames(permissions));
        }
        return isGranted;
    }

    @Override
    public boolean isGranted(@Nonnull String oakPath, @Nonnull String jcrActions) {
        TreeLocation location = TreeLocation.create(immutableRoot, oakPath);
        boolean isAcContent = acConfig.getContext().definesLocation(location);
        long permissions = Permissions.getPermissions(jcrActions, location, isAcContent);

        boolean isGranted = false;
        PropertyState property = location.getProperty();
        Tree tree = (property == null) ? location.getTree() : location.getParent().getTree();
        if (tree != null) {
            isGranted = isGranted(tree, property, permissions);
        } else if (!isVersionStorePath(oakPath)) {
            isGranted = compiledPermissions.isGranted(oakPath, permissions);
        }

        if (log.isTraceEnabled()) {
            logAccess(oakPath, isGranted, jcrActions);
        }
        return isGranted;
    }

    //---------------------------------------< AggregatedPermissionProvider >---
    @Override
    public boolean handles(@Nonnull String path, @Nonnull String jcrAction) {
        return true;
    }

    @Override
    public boolean handles(@Nonnull Tree tree, @Nonnull PrivilegeBits privilegeBits) {
        return true;
    }

    @Override
    public boolean handles(@Nonnull Tree tree, long permission) {
        return true;
    }

    @Override
    public boolean handles(@Nonnull TreePermission treePermission, long permission) {
        return true;
    }

    @Override
    public boolean handlesRepositoryPermissions() {
        return true;
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

    private boolean isAdmin(Set<Principal> principals) {
        Set<String> adminNames = acConfig.getParameters().getConfigValue(PARAM_ADMINISTRATIVE_PRINCIPALS, Collections.EMPTY_SET);
        for (Principal principal : principals) {
            if (principal instanceof AdminPrincipal || adminNames.contains(principal.getName())) {
                return true;
            }
        }
        return false;
    }

    private ImmutableTree getImmutableTree(@Nullable Tree tree) {
        if (tree instanceof ImmutableTree) {
            return (ImmutableTree) tree;
        } else {
            return (tree == null) ? null : (ImmutableTree) immutableRoot.getTree(tree.getPath());
        }
    }

    private static boolean isVersionStorePath(@Nonnull String oakPath) {
        if (oakPath.indexOf(JcrConstants.JCR_SYSTEM) == 1) {
            for (String p : VersionConstants.SYSTEM_PATHS) {
                if (oakPath.startsWith(p)) {
                    return true;
                }
            }
        }
        return false;
    }
}
