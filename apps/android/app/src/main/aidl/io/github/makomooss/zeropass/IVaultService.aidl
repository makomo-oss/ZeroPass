package io.github.makomooss.zeropass;

/**
 * The vault process (docs/spec/android.md §2): every call hands it one end of
 * a new socket pair, on which it answers the requests of docs/spec/ipc.md.
 */
interface IVaultService {
    void connect(in ParcelFileDescriptor socket);
}
