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
package org.apache.jackrabbit.oak.plugins.observation;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;
import static com.google.common.collect.Lists.newArrayList;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicReference;

import javax.jcr.observation.Event;
import javax.jcr.observation.EventIterator;
import javax.jcr.observation.EventListener;

import org.apache.jackrabbit.api.jmx.EventListenerMBean;
import org.apache.jackrabbit.commons.iterator.EventIteratorAdapter;
import org.apache.jackrabbit.commons.observation.ListenerTracker;
import org.apache.jackrabbit.oak.api.ContentSession;
import org.apache.jackrabbit.oak.core.ImmutableRoot;
import org.apache.jackrabbit.oak.core.ImmutableTree;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.plugins.observation.ChangeDispatcher.ChangeSet;
import org.apache.jackrabbit.oak.plugins.observation.ChangeDispatcher.Listener;
import org.apache.jackrabbit.oak.spi.state.NodeState;
import org.apache.jackrabbit.oak.spi.whiteboard.Registration;
import org.apache.jackrabbit.oak.spi.whiteboard.Whiteboard;
import org.apache.jackrabbit.oak.spi.whiteboard.WhiteboardUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@code ChangeProcessor} generates observation {@link javax.jcr.observation.Event}s
 * based on a {@link EventFilter} and delivers them to an {@link javax.jcr.observation.EventListener}.
 * <p>
 * After instantiation a {@code ChangeProcessor} must be started in order for its
 * {@link ListenerThread listener thread's} run methods to be regularly
 * executed and stopped in order to not execute its run method anymore.
 */
public class ChangeProcessor extends Thread {
    private static final Logger log = LoggerFactory.getLogger(ChangeProcessor.class);

    private final ContentSession contentSession;
    private final NamePathMapper namePathMapper;

    private volatile boolean stopping = false;

    private final Map<EventListener, ListenerThread> listeners = new HashMap<EventListener, ListenerThread>();

    private final Listener changeListener;

    public ChangeProcessor(
            ContentSession contentSession, NamePathMapper namePathMapper) {
        checkArgument(contentSession instanceof Observable);
        this.contentSession = contentSession;
        this.namePathMapper = namePathMapper;
        this.changeListener = ((Observable) contentSession).newListener();
    }

    public void addListener(EventListener listener, EventFilter filter) {
        if (listeners.containsKey(listener)) {
            ListenerThread lt = listeners.get(listener);
            lt.setFilter(filter);
        } else {
            ListenerThread lt = new ListenerThread(listener, filter);
            listeners.put(listener, lt);
            lt.setDaemon(true);
            lt.setPriority(Thread.MIN_PRIORITY);
            lt.start();
            System.out.println("Event listeners: " + listeners.size());
        }
    }

    public void removeListener(EventListener listener) {
        ListenerThread lt;
        synchronized (this) {
            lt = listeners.remove(listener);
        }
        if (lt != null) {
            // needs to happen outside synchronization
            lt.stopIt();
        }
    }

    public Collection<EventListener> getListeners() {
        return listeners.keySet();
    }

    /**
     * Start this change processor
     * @param whiteboard  the whiteboard instance to used for scheduling individual
     *                    runs of this change processor.
     * @throws IllegalStateException if started already
     */
    public synchronized void start(Whiteboard whiteboard) {
//        checkState(thread == null, "Change processor started already");

//        thread = new ListenerThread(whiteboard);
        this.setDaemon(true);
        this.setPriority(Thread.MIN_PRIORITY);
        this.start();
    }

    private ImmutableTree getTree(NodeState nodeState, String path) {
        return new ImmutableRoot(nodeState).getTree(path);
    }

    @Override
    public void run() {
        try {
            while (!stopping) {
                ChangeSet changes = changeListener.getChanges(100);
                for (ListenerThread lt : listeners.values()) {
                    EventFilter filter = lt.getFilter();

                    // FIXME don't rely on toString for session id
                    if (changes != null &&
                        filter.includeSessionLocal(changes.isLocal(contentSession.toString())) &&
                        filter.includeClusterExternal(changes.getCommitInfo() == null)) {
                        String path = namePathMapper.getOakPath(filter.getPath());
                        ImmutableTree beforeTree = getTree(changes.getBeforeState(), path);
                        ImmutableTree afterTree = getTree(changes.getAfterState(), path);
                        EventGenerator events = new EventGenerator(changes.getCommitInfo(),
                            beforeTree, afterTree, filter, namePathMapper);
                        if (events.hasNext()) {
                            lt.getQueue().offer(new EventIteratorAdapter(events));
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Error while dispatching observation events", e);
        }
    }


    /**
     * Stop this change processor if running. After returning from this methods no further
     * events will be delivered.
     * @throws IllegalStateException if not yet started or stopped already
     */
    public synchronized void stopIt() {
//        checkState(thread != null, "Change processor not started");
        checkState(!stopping, "Change processor already stopped");

        System.out.println("Stopping change processor");

        stopping = true;

        // stop our thread
        if (Thread.currentThread() != this) {
            try {
                this.join();
            } catch (InterruptedException e) {
                log.warn("Interruption while waiting for the observation thread to terminate", e);
                Thread.currentThread().interrupt();
            }
        }

        // stop all listener threads
        List<ListenerThread> toBeStopped;
        synchronized (this) {
            toBeStopped = newArrayList(listeners.values());
            listeners.clear();
        }
        for (ListenerThread lt : toBeStopped) {
            lt.stopIt();
        }

        changeListener.dispose();
    }

    //------------------------------------------------------------< private >---

    private class ListenerThread extends Thread {

//        private final Registration mbean;

//        private final AtomicReference<EventFilter> filterRef;
        private final EventListener listener;
        private EventFilter filter;

        private BlockingQueue<EventIterator> queue = new LinkedBlockingQueue<EventIterator>();

        private EventIterator POISON_PILL = new EventIterator() {
            @Override
            public Event nextEvent() {
                return null;
            }

            @Override
            public void skip(long skipNum) {
            }

            @Override
            public long getSize() {
                return 0;
            }

            @Override
            public long getPosition() {
                return 0;
            }

            @Override
            public boolean hasNext() {
                return false;
            }

            @Override
            public Object next() {
                return null;
            }

            @Override
            public void remove() {
            }
        };

        ListenerThread(EventListener listener, EventFilter filter) {
//            mbean = WhiteboardUtils.registerMBean(
//                    whiteboard, EventListenerMBean.class,
//                    tracker.getListenerMBean(), "EventListener",
//                    tracker.toString());
            this.listener = listener;
            this.filter = filter;
        }

        public void setFilter(EventFilter filter) {
            this.filter = filter;
        }

        @Override
        public void run() {
            try {
                while (true) {
                    EventIterator eventIterator = queue.take();
                    if (eventIterator == POISON_PILL) {
                        break;
                    }
                    listener.onEvent(eventIterator);
                }
            } catch (Exception e) {
                log.warn("Error while dispatching observation events", e);
            }
        }

        void dispose() {
//            mbean.unregister();
        }

        public EventFilter getFilter() {
            return filter;
        }

        public synchronized void stopIt() {
//        checkState(thread != null, "Change processor not started");
//            checkState(!stopping, "Listener thread already stopped");

            queue.offer(POISON_PILL);
            if (Thread.currentThread() != this) {
                try {
                    this.join();
                } catch (InterruptedException e) {
                    log.warn("Interruption while waiting for the observation thread to terminate", e);
                    Thread.currentThread().interrupt();
                } finally {
                    this.dispose();
                }
            }
        }

        private BlockingQueue<EventIterator> getQueue() {
            return queue;
        }
    }

}
