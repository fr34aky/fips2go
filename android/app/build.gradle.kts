import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Release signing lives outside the repo: android/keystore.properties
// (gitignored) points at the keystore. Absent → release builds unsigned,
// so clones without the key still compile.
val keystoreProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

android {
    namespace = "org.fips.android"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.fips.android"
        minSdk = 26
        targetSdk = 34
        versionCode = 8
        versionName = "0.2.0"
    }

    signingConfigs {
        if (keystoreProps.isNotEmpty()) {
            create("release") {
                storeFile = file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        // The Rust shim is built per-ABI by ../build-native.sh into
        // src/main/jniLibs/<abi>/libfips_android.so. abiFilters are set
        // per build type (defaultConfig would union with them): debug
        // packages everything in jniLibs, release ships only the
        // device-verified arm64-v8a.
        debug {
            ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
        }
        release {
            isMinifyEnabled = false
            // One ABI per release APK, selected via -PreleaseAbi=<abi>
            // (release-build.sh builds and verifies one APK per ABI).
            ndk { abiFilters += (findProperty("releaseAbi") as String? ?: "arm64-v8a") }
            signingConfigs.findByName("release")?.let { signingConfig = it }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.fragment:fragment-ktx:1.8.5")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
}
