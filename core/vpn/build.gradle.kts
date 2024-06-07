@Suppress("DSL_SCOPE_VIOLATION") // TODO: Remove once KTIJ-19369 is fixed
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

kotlin {
    jvmToolchain (11)
}

android {
    namespace = "de.tomcory.heimdall.core.vpn"

    defaultConfig {
        compileSdk = 34
        minSdk = 26 // Todo: Talk to Tom and maybe reset to 24
    }
}

dependencies {
    implementation (libs.timber)
    implementation (libs.lifecycle.runtime.ktx)

    // Room dependencies
    implementation (libs.androidx.room.ktx)

    implementation (libs.bouncycastle.bcpkix.jdk15on)
    implementation (libs.guava)
    implementation (libs.netty.all) { exclude(group = "org.slf4j") }

    // pcap4j
    implementation (libs.pcap4j.core)
    implementation (libs.pcap4j.packetfactory.static)

    implementation (project(":core:database"))
    implementation (project(":core:util"))

    // QUIC Stuff
    implementation ("at.favre.lib:hkdf:2.0.0")
    implementation ("org.glassfish:javax.json:1.1.4")
    implementation ("commons-cli:commons-cli:1.4")
    implementation ("com.google.firebase:firebase-crashlytics-buildtools:2.9.9")
    implementation ("tech.kwik:qpack:1.0.2")

}