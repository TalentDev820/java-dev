package com.r.crypto.util;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.util.Arrays.asList;

public class Util {
    public static String quote(Object o) {
        return o == null ? "null" : "\"" + o + "\"";
    }

    public static String toSimpleString(Object o) {
        if (o == null) {
            return null;
        } else if (o.getClass().isArray() && !o.getClass().getComponentType().isPrimitive()) {
            return o.getClass().getSimpleName() + "[" + ((Object[]) o).length + "]" + "@" + System.identityHashCode(o);
        } else if (o instanceof Optional) {
            return "Optional[" + (((Optional<?>) o).isPresent() ? "present" : "empty") + "]" + "@" + System.identityHashCode(o);
        } else {
            return o.getClass().getSimpleName() + "@" + System.identityHashCode(o);
        }
    }

    public static boolean isEmpty(String s) {
        return s == null || s.isEmpty();
    }

    public static boolean isEmpty(Object[] objects) {
        return objects == null || objects.length == 0;
    }

    public static boolean isEmpty(Collection<?> collection) {
        return collection == null || collection.size() == 0;
    }

    public static boolean isEmpty(Map<?, ?> map) {
        return map == null || map.size() == 0;
    }

    public static String mask(Object plaintext) {
        return plaintext == null ? null : "****";
        // return debugMask(plaintext);
    }

    private static String debugMask(Object plaintext) {
        if (plaintext == null) {
            return null;
        } else if (plaintext instanceof byte[]) {
            return quote(new String((byte[]) plaintext));
        } else if (plaintext instanceof CharSequence) {
            return quote(plaintext);
        } else {
            return plaintext.toString();
        }
    }

    public static Object[] array(Object... objects) {
        return objects;
    }

    /** Like Arrays.asList(), but won't NPE if called as list(null) */
    @SafeVarargs
    @SuppressWarnings("varargs")
    public static <T> List<T> list(T... objects) {
        return objects == null ? null : asList(objects);
    }

    @SafeVarargs
    @SuppressWarnings("varargs")
    public static <T> Set<T> set(T... objects) {
        return objects == null ? null : new HashSet<>(list(objects));
    }

    public static byte[] concat(byte[]... arrays) {
        if (arrays == null) {
            return null;
        }

        if (arrays.length == 1) {
            return arrays[0];
        }

        int size = arrays[0].length;
        for (int i = 1; i < arrays.length; i++) {
            size += arrays[i].length;
        }

        byte[] result = new byte[size];
        int position = 0;
        for (byte[] bytes : arrays) {
            System.arraycopy(bytes, 0, result, position, bytes.length);
            position += bytes.length;
        }

        return result;
    }

    public static byte[][] split(byte[] array, int... sizes) {
        if (array == null) {
            return null;
        }

        if (sizes == null || sizes[0] == array.length) {
            return new byte[][] { array };
        }

        byte[][] result = new byte[sizes.length][];
        for (int arrayIndex = 0, sizeIndex = 0; sizeIndex < sizes.length; arrayIndex += sizes[sizeIndex], sizeIndex++) {
            int size = sizes[sizeIndex];
            if (size == -1) {
                if (sizeIndex < sizes.length - 1) {
                    throw new IllegalArgumentException("max array size cannot be specified before the end");
                }
                result[sizeIndex] = Arrays.copyOfRange(array, arrayIndex, array.length);
            } else {
                result[sizeIndex] = Arrays.copyOfRange(array, arrayIndex, arrayIndex + size);
            }
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    public static <T> T cast(Object o) {
        return (T) o;
    }

    public static Throwable findCause(Throwable t, Class<? extends Throwable> causeClass) {
        while (t != null) {
            if (t.getClass() == causeClass) {
                return t;
            } else {
                t = t.getCause();
            }
        }
        return null;
    }
}
