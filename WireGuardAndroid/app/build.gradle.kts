plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "com.change.wg"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.change.wg"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        // Only 64-bit ABIs — our Curve25519 uses __uint128_t which
        // isn't available on 32-bit ARM. Google Play requires 64-bit
        // since Aug 2019 anyway.
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    // NDK: cross-compile our C library (libwg_session.so) for Android
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    ndkVersion = "27.2.12479018"
}


dependencies {
    // Compose BOM
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.navigation:navigation-compose:2.8.5")

    // WireGuard tunnel (Go-based userspace implementation)
    implementation("com.wireguard.android:tunnel:1.0.20230706")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    // DataStore (SharedPreferences replacement for node persistence)
    implementation("androidx.datastore:datastore-preferences:1.1.1")

    // JSON serialization
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    // HTTP client. Used by AuthClient + MeshClient against the Polar
    // control plane (/api/login + /v1/register + /v1/heartbeat). Cookie
    // jar keeps the session after /api/login so the app can mint mesh
    // tokens on behalf of the logged-in user later.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}
