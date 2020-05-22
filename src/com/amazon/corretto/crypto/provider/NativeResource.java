// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import static com.amazon.corretto.crypto.provider.Loader.RESOURCE_JANITOR;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.LongConsumer;
import java.util.function.LongFunction;

class NativeResource {
    /**
     * For tests. Makes a best-effort attempt to awaken any sleeping cleaner threads.
     */
    @SuppressWarnings("unused") // invoked reflectively
    private static void wakeCleaner() {
        RESOURCE_JANITOR.wake();
    }

    private static final class Cell extends ReentrantReadWriteLock {
        private static final long serialVersionUID = 1L;
        // @GuardedBy("this") // Restore once replacement for JSR-305 available
        private final long ptr;
        private final LongConsumer releaser;
        private final boolean isThreadSafe;
        // @GuardedBy("this") // Restore once replacement for JSR-305 available
        private boolean released;

        private Cell(final long ptr, final LongConsumer releaser, boolean isThreadSafe) {
            if (ptr == 0) {
              throw new AssertionError("ptr must not be equal to zero");
            }
            this.ptr = ptr;
            this.releaser = releaser;
            this.released = false;
            this.isThreadSafe = isThreadSafe;
        }

        private CloseableLock getLock(boolean writeLock) {
            if (!isThreadSafe || writeLock) {
                return new CloseableLock(writeLock());
            } else {
                return new CloseableLock(readLock());
            }
        }

        @SuppressWarnings("try") // For "unused" lock variable in try-with-resources
        public void release() {
            try (CloseableLock lock = getLock(true)) {
                if (released) return;

                released = true;
                releaser.accept(ptr);
            }
        }

        @SuppressWarnings("try") // For "unused" lock variable in try-with-resources
        public long take() {
            try (CloseableLock lock = getLock(true)) {
                if (released) {
                    throw new IllegalStateException("Use after free");
                }

                released = true;
                return ptr;
            }
        }

        @SuppressWarnings("try") // For "unused" lock variable in try-with-resources
        public boolean isReleased() {
            try (CloseableLock lock = getLock(true)) {
                return released;
            }
        }

        /**
         * Calls the supplied {@link LongFunction} passing in the raw handle as a parameter and return
         * the result.
         */
        // @CheckReturnValue // Restore once replacement for JSR-305 available
        @SuppressWarnings("try") // For "unused" lock variable in try-with-resources
        public <T> T use(LongFunction<T> function) {
            try (CloseableLock lock = getLock(false)) {
                if (released) {
                    throw new IllegalStateException("Use after free");
                }
                return function.apply(ptr);
            }
        }
    }

    private static final class CloseableLock implements AutoCloseable {
        private final Lock lock;

        CloseableLock(Lock lock) {
            this.lock = lock;
            this.lock.lock();
        }

        @Override
        public void close() {
            lock.unlock();
        }

    }

    private final Cell cell;
    private final Janitor.Mess mess;

    protected NativeResource(long ptr, LongConsumer releaser) {
        this(ptr, releaser, false);
    }

    protected NativeResource(long ptr, LongConsumer releaser, boolean isThreadSafe) {
        cell = new Cell(ptr, releaser, isThreadSafe);

        mess = RESOURCE_JANITOR.register(this, cell::release);
    }

    boolean isReleased() {
        return cell.isReleased();
    }

    /**
     * Calls the supplied {@link LongFunction} passing in the raw handle as a parameter and return
     * the result.
     */
    // @CheckReturnValue // Restore once replacement for JSR-305 available
    <T> T use(LongFunction<T> function) {
        return cell.use(function);
    }

    /**
     * Calls the supplied {@link LongConsumer} passing in the raw handle as a parameter.
     */
    void useVoid(LongConsumer function) {
        @SuppressWarnings("unused")
        Object unused = cell.use(ptr -> {
            function.accept(ptr);
            return null;
        });
    }

    /**
     * Returns the raw pointer and passes all responsibility to releasing it to the caller.
     * @return ptr
     */
    // @CheckReturnValue // Restore once replacement for JSR-305 available
    long take() {
        long result = cell.take();
        mess.clean();
        return result;
    }

    void release() {
        mess.clean();
    }
}
