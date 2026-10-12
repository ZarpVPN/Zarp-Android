plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

val abis = listOf("arm64-v8a", "armeabi-v7a", "x86_64")

// Release signing comes from the environment (GitHub Actions secrets), never from the repo.
val keystoreFile = providers.environmentVariable("ZARP_KEYSTORE_FILE").orNull

android {
    namespace = "io.github.feg55.zarp"
    compileSdk = 37
    buildToolsVersion = "36.1.0"
    ndkVersion = "29.0.14206865"

    defaultConfig {
        applicationId = "io.github.feg55.zarp"
        minSdk = 26
        targetSdk = 36
        // CI passes -Pzarp.versionCode / -Pzarp.versionName from the release tag
        versionCode = providers.gradleProperty("zarp.versionCode").orNull?.toInt() ?: 1
        versionName = providers.gradleProperty("zarp.versionName").orNull ?: "0.1.0"

        ndk { abiFilters += abis }
        externalNativeBuild {
            ndkBuild {
                // JNI class for hev-socks5-tunnel: io.github.feg55.zarp.vpn.TProxyService
                cFlags += "-DPKGNAME=io/github/feg55/zarp/vpn"
                targets += "hev-socks5-tunnel"
            }
        }
    }

    externalNativeBuild {
        ndkBuild { path = file("src/main/jni/Android.mk") }
    }

    signingConfigs {
        if (keystoreFile != null) {
            create("release") {
                storeFile = file(keystoreFile)
                storePassword = providers.environmentVariable("ZARP_KEYSTORE_PASSWORD").get()
                keyAlias = providers.environmentVariable("ZARP_KEY_ALIAS").get()
                keyPassword = providers.environmentVariable("ZARP_KEY_PASSWORD").get()
            }
        }
    }

    buildTypes {
        debug {
            // installs next to the release build instead of replacing it
            applicationIdSuffix = ".debug"
            resValue("string", "app_name", "Zarp debug")
        }
        release {
            resValue("string", "app_name", "Zarp")
            // without the variables the release APK stays unsigned
            signingConfig = signingConfigs.findByName("release")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
        resValues = true
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    lint {
        abortOnError = true
        warningsAsErrors = false
        // the Go core and hev are native; lint cannot see their JNI entry points
        disable += "UnsafeDynamicallyLoadedCode"
    }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }
    packaging { jniLibs { useLegacyPackaging = true } }
}

// ---------------------------------------------------------------- Go core (MASQUE)

val goCoreDir = rootProject.layout.projectDirectory.dir("core")
val goCoreAar = layout.projectDirectory.file("libs/zarpcore.aar")

val sdkDir = androidComponents.sdkComponents.sdkDirectory
val ndkDir = androidComponents.sdkComponents.ndkDirectory

val buildGoCore = tasks.register<Exec>("buildGoCore") {
    group = "build"
    description = "Builds core/ (usque MASQUE + Zarp tunnel) into libs/zarpcore.aar with gomobile."
    inputs.files(fileTree(goCoreDir) { include("**/*.go", "go.mod", "go.sum") })
        .withPropertyName("goSources")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.files(rootProject.layout.projectDirectory.dir("scripts").asFileTree)
        .withPropertyName("buildScripts")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.property("abis", abis)
    outputs.file(goCoreAar)

    val isWindows = System.getProperty("os.name").startsWith("Windows", ignoreCase = true)
    val goTargets = abis.joinToString(",") {
        when (it) {
            "arm64-v8a" -> "android/arm64"
            "armeabi-v7a" -> "android/arm"
            "x86_64" -> "android/amd64"
            else -> error("unsupported ABI $it")
        }
    }
    val script = rootProject.layout.projectDirectory.file(
        if (isWindows) "scripts/build-core.cmd" else "scripts/build-core.sh"
    ).asFile

    workingDir = goCoreDir.asFile
    // locals, so the configuration cache does not capture the build script
    val sdk = sdkDir
    val ndk = ndkDir
    doFirst {
        environment("ANDROID_HOME", sdk.get().asFile.absolutePath)
        environment("ANDROID_NDK_HOME", ndk.get().asFile.absolutePath)
    }
    environment("ZARP_GO_TARGETS", goTargets)
    environment("ZARP_CORE_OUT", goCoreAar.asFile.absolutePath)
    if (isWindows) commandLine("cmd", "/c", script.absolutePath) else commandLine("sh", script.absolutePath)
}

tasks.named("preBuild") { dependsOn(buildGoCore) }

dependencies {
    implementation(files(goCoreAar))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.service)
    implementation(libs.androidx.datastore.preferences)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)
    debugImplementation(libs.compose.ui.tooling)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}
