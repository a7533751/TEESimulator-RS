package android.security.keymaster;

import android.os.Parcel;
import android.os.Parcelable;

/** Compile-only declaration for the Android 9 Keymaster blob wrapper. */
public class KeymasterBlob implements Parcelable {
    public final byte[] blob;

    public KeymasterBlob(byte[] blob) { this.blob = blob; }

    @Override public void writeToParcel(Parcel dest, int flags) { throw new UnsupportedOperationException("STUB!"); }
    @Override public int describeContents() { return 0; }

    public static final Creator<KeymasterBlob> CREATOR = new Creator<KeymasterBlob>() {
        @Override public KeymasterBlob createFromParcel(Parcel in) { throw new UnsupportedOperationException("STUB!"); }
        @Override public KeymasterBlob[] newArray(int size) { return new KeymasterBlob[size]; }
    };
}
