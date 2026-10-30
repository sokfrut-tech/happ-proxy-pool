plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.sokfrut.happclient"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.sokfrut.happclient"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0-prototype"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    // libXray AAR собирается в CI из закреплённого тега и кладётся сюда; в git не хранится.
    implementation(mapOf("name" to "libXray", "ext" to "aar"))
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
