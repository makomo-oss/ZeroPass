plugins {
    id("com.android.application")
}

android {
    namespace = "io.github.makomooss.zeropass"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.makomooss.zeropass"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.0.0"
        ndk {
            // The Rust core is built for this ABI only (build-core.sh).
            abiFilters += "arm64-v8a"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        // The generated bindings are not ours to lint.
        abortOnError = false
    }
}

dependencies {
    // Loads the Rust core (UniFFI's Kotlin bindings call it through JNA).
    implementation("net.java.dev.jna:jna:5.19.1@aar")
    implementation("androidx.activity:activity:1.13.0")
    implementation("androidx.camera:camera-camera2:1.6.2")
    implementation("androidx.camera:camera-lifecycle:1.6.2")
    implementation("androidx.camera:camera-view:1.6.2")
    // QR decoding on the device, without any network service.
    implementation("com.google.zxing:core:3.5.4")
}
