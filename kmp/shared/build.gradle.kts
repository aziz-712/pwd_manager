// Kotlin Multiplatform client core.
//
// The rule this module exists to enforce: the vault format and key hierarchy are
// written ONCE, in commonMain, and every platform shares them. Only the calls
// into libsodium and into the OS keystore are per-platform, because those are
// the only genuinely platform-specific things.
plugins {
    kotlin("multiplatform") version "2.0.21"
    kotlin("plugin.serialization") version "2.0.21"
    id("com.android.library") version "8.5.2"
}

kotlin {
    androidTarget()
    jvm()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
                implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.6.1")
                implementation("io.ktor:ktor-client-core:2.3.12")
                implementation("io.ktor:ktor-client-content-negotiation:2.3.12")
                implementation("io.ktor:ktor-serialization-kotlinx-json:2.3.12")
            }
        }
        val commonTest by getting {
            dependencies { implementation(kotlin("test")) }
        }
        val androidMain by getting {
            dependencies {
                // libsodium for Android: Argon2id, XChaCha20-Poly1305, BLAKE2b.
                implementation("com.goterl:lazysodium-android:5.1.0@aar")
                implementation("net.java.dev.jna:jna:5.14.0@aar")
                implementation("androidx.biometric:biometric:1.2.0-alpha05")
                implementation("io.ktor:ktor-client-okhttp:2.3.12")
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation("com.goterl:lazysodium-java:5.1.4")
                implementation("net.java.dev.jna:jna:5.14.0")
                implementation("io.ktor:ktor-client-okhttp:2.3.12")
            }
        }
        val iosMain by creating {
            dependsOn(commonMain)
            dependencies { implementation("io.ktor:ktor-client-darwin:2.3.12") }
        }
        val iosArm64Main by getting { dependsOn(iosMain) }
        val iosSimulatorArm64Main by getting { dependsOn(iosMain) }
    }
}

android {
    namespace = "dev.zkvault.core"
    compileSdk = 35
    defaultConfig {
        minSdk = 28 // StrongBox and modern Keystore semantics
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}
