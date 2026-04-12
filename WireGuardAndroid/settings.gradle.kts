pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolution {
    repositories {
        google()
        mavenCentral()
        // WireGuard Android tunnel library
        maven { url = uri("https://raw.githubusercontent.com/nickoala/tailscale-android/maven-repo/") }
    }
}

rootProject.name = "WireGuardAndroid"
include(":app")
