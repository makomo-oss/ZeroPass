plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "io.github.makomooss.zeropass"
    compileSdk {
        // The Compose libraries need 37.2; the app still targets 36.
        version = release(37) { minorApiLevel = 2 }
    }

    defaultConfig {
        applicationId = "io.github.makomooss.zeropass"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.0.0"
        ndk {
            // The ABIs build-core.sh builds the Rust core for: phones and the
            // emulator.
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildFeatures {
        // The vault service's Binder interface (IVaultService.aidl).
        aidl = true
        // Debug builds allow screenshots and adb-driven actions.
        buildConfig = true
        compose = true
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
    // The screens (docs/spec/android.md §4).
    implementation(platform("androidx.compose:compose-bom:2026.11.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.11.1")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.1")
    // The prompt that unlocks the Keystore key (docs/spec/android.md §3).
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment-ktx:1.9.1")
    implementation("androidx.camera:camera-camera2:1.6.2")
    implementation("androidx.camera:camera-lifecycle:1.6.2")
    implementation("androidx.camera:camera-view:1.6.2")
    // QR decoding on the device, without any network service.
    implementation("com.google.zxing:core:3.5.4")
}
