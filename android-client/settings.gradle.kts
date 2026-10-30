pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // libXray.aar собирается в CI в app/libs; flatDir — правильный способ подключить AAR.
        flatDir { dirs("app/libs") }
    }
}
rootProject.name = "HappCompatibleClient"
include(":app")
