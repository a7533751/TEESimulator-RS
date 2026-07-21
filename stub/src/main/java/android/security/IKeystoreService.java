package android.security;

/**
 * Compile-only declaration for the Android 9 synchronous Keystore Binder service.
 *
 * The framework's boot class provides the real generated Stub at runtime. Keeping this declaration
 * intentionally small lets the interceptor resolve transaction constants reflectively on the
 * target device without shipping a duplicate Binder implementation.
 */
public interface IKeystoreService {
    String DESCRIPTOR = "android.security.IKeystoreService";

    class Stub {}
}
