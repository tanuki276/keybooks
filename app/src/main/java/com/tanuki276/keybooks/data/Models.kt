package com.tanuki276.keybooks.data

enum class AuthType {
    NONE,
    BIOMETRIC,
    PASSWORD
}

data class ProjectItem(
    val id: Long,
    val name: String,
    val createdAt: Long
)

data class ServiceItem(
    val id: Long,
    val projectId: Long,
    val name: String,
    val createdAt: Long
)

data class SecretItem(
    val id: Long,
    val serviceId: Long,
    val name: String,
    val encryptedValue: ByteArray,
    val iv: ByteArray,
    val hidden: Boolean,
    val authType: AuthType,
    val passwordSalt: ByteArray?,
    val createdAt: Long
)

data class ServiceBundle(
    val service: ServiceItem,
    val secrets: List<SecretItem>
)
