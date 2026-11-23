// A login form for testing ZeroPass's autofill service on the emulator
// (docs/spec/android.md §6.2). Never shipped.
plugins {
    id("com.android.application")
}

android {
    namespace = "io.github.makomooss.zeropass.testapp"
    compileSdk {
        version = release(37) { minorApiLevel = 2 }
    }

    defaultConfig {
        applicationId = "io.github.makomooss.zeropass.testapp"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.0.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
