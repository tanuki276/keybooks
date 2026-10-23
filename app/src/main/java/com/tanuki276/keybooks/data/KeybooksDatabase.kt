package com.tanuki276.keybooks.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import com.tanuki276.keybooks.security.CryptoManager
import org.json.JSONObject
import org.json.JSONArray
import java.util.Base64
import java.util.UUID

class KeybooksDatabase(
    context: Context,
    private val cryptoManager: CryptoManager
) : SQLiteOpenHelper(
    context.applicationContext,
    DATABASE_NAME,
    null,
    DATABASE_VERSION
) {
    override fun onConfigure(db: SQLiteDatabase) {
        super.onConfigure(db)
        db.setForeignKeyConstraintsEnabled(true)
    }

    override fun onCreate(db: SQLiteDatabase) {
        createV2Schema(db)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 2) migrateV1ToV2(db)
    }

    fun insertProject(name: String): Long {
        val recordId = UUID.randomUUID().toString()
        val encrypted = cryptoManager.encryptMetadata(
            name.trim(),
            metadataAad(TYPE_PROJECT, recordId)
        )
        val values = ContentValues().apply {
            put("record_id", recordId)
            put("encrypted_metadata", encrypted.encryptedValue)
            put("metadata_iv", encrypted.iv)
            put("created_at", System.currentTimeMillis())
        }
        return writableDatabase.insertOrThrow("projects", null, values)
    }

    fun insertService(projectId: Long, name: String): Long {
        val recordId = UUID.randomUUID().toString()
        val encrypted = cryptoManager.encryptMetadata(
            name.trim(),
            metadataAad(TYPE_SERVICE, recordId)
        )
        val values = ContentValues().apply {
            put("record_id", recordId)
            put("project_id", projectId)
            put("encrypted_metadata", encrypted.encryptedValue)
            put("metadata_iv", encrypted.iv)
            put("created_at", System.currentTimeMillis())
        }
        return writableDatabase.insertOrThrow("services", null, values)
    }

    fun insertSecret(
        serviceId: Long,
        name: String,
        encryptedValue: ByteArray,
        iv: ByteArray,
        hidden: Boolean,
        authType: AuthType,
        passwordSalt: ByteArray?,
        recovery: com.tanuki276.keybooks.security.EncryptedPayload? = null
    ): Long {
        val recordId = UUID.randomUUID().toString()
        val metadataJson = JSONObject().apply {
            put("name", name.trim())
            put("hidden", hidden)
            put("authType", authType.name)
            put("valueDigest", Base64.getEncoder().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(encryptedValue + iv)))
            if (recovery != null) put("recovery", JSONObject()
                .put("value", Base64.getEncoder().encodeToString(recovery.encryptedValue))
                .put("iv", Base64.getEncoder().encodeToString(recovery.iv))
                .put("salt", Base64.getEncoder().encodeToString(recovery.passwordSalt)))
            if (passwordSalt != null) {
                put("passwordSalt", Base64.getEncoder().encodeToString(passwordSalt))
            }
        }.toString()
        val encryptedMetadata = cryptoManager.encryptMetadata(
            metadataJson,
            metadataAad(TYPE_SECRET, recordId)
        )

        val values = ContentValues().apply {
            put("record_id", recordId)
            put("service_id", serviceId)
            put("encrypted_metadata", encryptedMetadata.encryptedValue)
            put("metadata_iv", encryptedMetadata.iv)
            put("encrypted_value", encryptedValue)
            put("iv", iv)
            put("created_at", System.currentTimeMillis())
        }
        return writableDatabase.insertOrThrow("secrets", null, values)
    }

    fun rename(table: String, id: Long, name: String) {
        require(table in setOf("projects", "services", "secrets"))
        require(name.isNotBlank())
        writableDatabase.query(table, arrayOf("record_id", "encrypted_metadata", "metadata_iv"),
            "id = ?", arrayOf(id.toString()), null, null, null).use { cursor ->
            check(cursor.moveToFirst())
            val type = when (table) { "projects" -> TYPE_PROJECT; "services" -> TYPE_SERVICE; else -> TYPE_SECRET }
            val text = if (table == "secrets") {
                JSONObject(decryptMetadata(type, cursor.getString(0), cursor.getBlob(1), cursor.getBlob(2)))
                    .put("name", name.trim()).toString()
            } else name.trim()
            val encrypted = cryptoManager.encryptMetadata(text, metadataAad(type, cursor.getString(0)))
            val values = ContentValues().apply {
                put("encrypted_metadata", encrypted.encryptedValue); put("metadata_iv", encrypted.iv)
            }
            check(writableDatabase.update(table, values, "id = ?", arrayOf(id.toString())) == 1)
        }
    }

    fun delete(table: String, id: Long) {
        require(table in setOf("projects", "services", "secrets"))
        check(writableDatabase.delete(table, "id = ?", arrayOf(id.toString())) == 1)
    }

    fun replaceSecret(id: Long, serviceId: Long, name: String,
        payload: com.tanuki276.keybooks.security.EncryptedPayload, hidden: Boolean, auth: AuthType,
        recovery: com.tanuki276.keybooks.security.EncryptedPayload? = null) {
        val db = writableDatabase
        db.beginTransaction()
        try {
            insertSecret(serviceId, name, payload.encryptedValue, payload.iv, hidden, auth, payload.passwordSalt, recovery)
            delete("secrets", id)
            db.setTransactionSuccessful()
        } finally { db.endTransaction() }
    }

    /** Authenticated, fully validated before any persistent mutation. Import merges without deleting existing data. */
    fun importPortable(text: String, password: String) {
        val root = JSONObject(text)
        require(root.getInt("version") == 1)
        val projects = root.getJSONArray("projects")
        require(projects.length() <= 10_000)
        // Parse the complete document before writing; limits also prevent pathological nesting/record counts.
        var count = 0
        for (i in 0 until projects.length()) {
            val project = projects.getJSONObject(i)
            require(project.getString("name").isNotBlank())
            val services = project.getJSONArray("services")
            for (j in 0 until services.length()) {
                val service = services.getJSONObject(j)
                require(service.getString("name").isNotBlank())
                val secrets = service.getJSONArray("secrets")
                for (k in 0 until secrets.length()) {
                    val secret = secrets.getJSONObject(k)
                    require(secret.getString("name").isNotBlank())
                    secret.getString("value"); secret.getBoolean("hidden")
                    count++
                    require(count <= 10_000)
                }
            }
        }
        val db = writableDatabase
        db.beginTransaction()
        try {
            for (i in 0 until projects.length()) {
                val project = projects.getJSONObject(i)
                val projectId = insertProject(project.getString("name"))
                val services = project.getJSONArray("services")
                for (j in 0 until services.length()) {
                    val service = services.getJSONObject(j)
                    val serviceId = insertService(projectId, service.getString("name"))
                    val secrets = service.getJSONArray("secrets")
                    for (k in 0 until secrets.length()) {
                        val secret = secrets.getJSONObject(k)
                        val payload = cryptoManager.encryptWithPassword(secret.getString("value"), password)
                        insertSecret(serviceId, secret.getString("name"), payload.encryptedValue, payload.iv,
                            secret.getBoolean("hidden"), AuthType.PASSWORD, payload.passwordSalt)
                    }
                }
            }
            db.setTransactionSuccessful()
        } finally { db.endTransaction() }
    }

    fun getProjects(): List<ProjectItem> {
        val result = mutableListOf<ProjectItem>()
        readableDatabase.query(
            "projects",
            arrayOf("id", "record_id", "encrypted_metadata", "metadata_iv", "created_at"),
            null, null, null, null,
            "created_at DESC"
        ).use { cursor ->
            while (cursor.moveToNext()) {
                val id = cursor.getLong(0)
                val recordId = cursor.getString(1)
                val name = runCatching { decryptMetadata(
                    TYPE_PROJECT,
                    recordId,
                    cursor.getBlob(2),
                    cursor.getBlob(3)
                )
                }.getOrNull()
                result += ProjectItem(id, name ?: "復旧が必要なプロジェクト #$id", cursor.getLong(4), name != null)
            }
        }
        return result
    }

    fun getProjectServices(projectId: Long): List<ServiceBundle> {
        val services = mutableListOf<ServiceItem>()
        readableDatabase.query(
            "services",
            arrayOf("id", "record_id", "project_id", "encrypted_metadata", "metadata_iv", "created_at"),
            "project_id = ?",
            arrayOf(projectId.toString()),
            null, null,
            "created_at ASC"
        ).use { cursor ->
            while (cursor.moveToNext()) {
                val id = cursor.getLong(0)
                val recordId = cursor.getString(1)
                val name = runCatching { decryptMetadata(TYPE_SERVICE, recordId, cursor.getBlob(3), cursor.getBlob(4)) }.getOrNull()
                services += ServiceItem(
                    id = id,
                    projectId = cursor.getLong(2),
                    name = name ?: "復旧が必要なサービス #$id",
                    createdAt = cursor.getLong(5),
                    readable = name != null
                )
            }
        }
        return services.map { ServiceBundle(it, getSecrets(it.id)) }
    }

    private fun getSecrets(serviceId: Long): List<SecretItem> {
        val result = mutableListOf<SecretItem>()
        readableDatabase.query(
            "secrets",
            arrayOf(
                "id", "record_id", "service_id", "encrypted_metadata", "metadata_iv",
                "encrypted_value", "iv", "created_at"
            ),
            "service_id = ?",
            arrayOf(serviceId.toString()),
            null, null,
            "created_at ASC"
        ).use { cursor ->
            while (cursor.moveToNext()) {
                try {
                val recordId = cursor.getString(1)
                val metadata = JSONObject(
                    decryptMetadata(TYPE_SECRET, recordId, cursor.getBlob(3), cursor.getBlob(4))
                )
                if (metadata.has("valueDigest")) {
                    val digest = java.security.MessageDigest.getInstance("SHA-256").digest(cursor.getBlob(5) + cursor.getBlob(6))
                    check(java.security.MessageDigest.isEqual(digest, Base64.getDecoder().decode(metadata.getString("valueDigest")))) { "Secret integrity failure" }
                }
                val passwordSalt = metadata.optString("passwordSalt")
                    .takeIf { it.isNotBlank() }
                    ?.let { Base64.getDecoder().decode(it) }

                result += SecretItem(
                    id = cursor.getLong(0),
                    serviceId = cursor.getLong(2),
                    name = metadata.getString("name"),
                    encryptedValue = cursor.getBlob(5),
                    iv = cursor.getBlob(6),
                    hidden = metadata.getBoolean("hidden"),
                    authType = AuthType.valueOf(metadata.getString("authType")),
                    passwordSalt = passwordSalt,
                    createdAt = cursor.getLong(7),
                    recovery = metadata.optJSONObject("recovery")?.let {
                        com.tanuki276.keybooks.security.EncryptedPayload(
                            Base64.getDecoder().decode(it.getString("value")),
                            Base64.getDecoder().decode(it.getString("iv")),
                            Base64.getDecoder().decode(it.getString("salt")))
                    }
                )
                } catch (_: Exception) {
                    result += SecretItem(cursor.getLong(0), cursor.getLong(2),
                        "復旧が必要な項目 #${cursor.getLong(0)}", byteArrayOf(), byteArrayOf(),
                        true, AuthType.NONE, null, cursor.getLong(7), readable = false)
                }
            }
        }
        return result
    }

    private fun decryptMetadata(
        type: String,
        recordId: String,
        encryptedMetadata: ByteArray,
        metadataIv: ByteArray
    ): String = cryptoManager.decryptMetadata(
        encryptedMetadata,
        metadataIv,
        metadataAad(type, recordId)
    )

    private fun migrateV1ToV2(db: SQLiteDatabase) {
        db.beginTransaction()
        try {
            db.execSQL("PRAGMA foreign_keys=OFF")
            db.execSQL("ALTER TABLE projects RENAME TO projects_v1")
            db.execSQL("ALTER TABLE services RENAME TO services_v1")
            db.execSQL("ALTER TABLE secrets RENAME TO secrets_v1")
            createV2Schema(db)

            db.rawQuery("SELECT id, name, created_at FROM projects_v1", null).use { cursor ->
                while (cursor.moveToNext()) {
                    val id = cursor.getLong(0)
                    val recordId = UUID.randomUUID().toString()
                    val encrypted = cryptoManager.encryptMetadata(
                        cursor.getString(1),
                        metadataAad(TYPE_PROJECT, recordId)
                    )
                    val values = ContentValues().apply {
                        put("id", id)
                        put("record_id", recordId)
                        put("encrypted_metadata", encrypted.encryptedValue)
                        put("metadata_iv", encrypted.iv)
                        put("created_at", cursor.getLong(2))
                    }
                    db.insertOrThrow("projects", null, values)
                }
            }

            db.rawQuery("SELECT id, project_id, name, created_at FROM services_v1", null).use { cursor ->
                while (cursor.moveToNext()) {
                    val id = cursor.getLong(0)
                    val recordId = UUID.randomUUID().toString()
                    val encrypted = cryptoManager.encryptMetadata(
                        cursor.getString(2),
                        metadataAad(TYPE_SERVICE, recordId)
                    )
                    val values = ContentValues().apply {
                        put("id", id)
                        put("record_id", recordId)
                        put("project_id", cursor.getLong(1))
                        put("encrypted_metadata", encrypted.encryptedValue)
                        put("metadata_iv", encrypted.iv)
                        put("created_at", cursor.getLong(3))
                    }
                    db.insertOrThrow("services", null, values)
                }
            }

            db.rawQuery(
                "SELECT id, service_id, name, encrypted_value, iv, hidden, auth_type, password_salt, created_at FROM secrets_v1",
                null
            ).use { cursor ->
                while (cursor.moveToNext()) {
                    val id = cursor.getLong(0)
                    val recordId = UUID.randomUUID().toString()
                    val metadataJson = JSONObject().apply {
                        put("name", cursor.getString(2))
                        put("hidden", cursor.getInt(5) == 1)
                        put("authType", cursor.getString(6))
                        if (!cursor.isNull(7)) {
                            put("passwordSalt", Base64.getEncoder().encodeToString(cursor.getBlob(7)))
                        }
                    }.toString()
                    val encryptedMetadata = cryptoManager.encryptMetadata(
                        metadataJson,
                        metadataAad(TYPE_SECRET, recordId)
                    )
                    val values = ContentValues().apply {
                        put("id", id)
                        put("record_id", recordId)
                        put("service_id", cursor.getLong(1))
                        put("encrypted_metadata", encryptedMetadata.encryptedValue)
                        put("metadata_iv", encryptedMetadata.iv)
                        put("encrypted_value", cursor.getBlob(3))
                        put("iv", cursor.getBlob(4))
                        put("created_at", cursor.getLong(8))
                    }
                    db.insertOrThrow("secrets", null, values)
                }
            }

            db.execSQL("DROP TABLE secrets_v1")
            db.execSQL("DROP TABLE services_v1")
            db.execSQL("DROP TABLE projects_v1")
            db.execSQL("PRAGMA foreign_keys=ON")
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    private fun createV2Schema(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id TEXT NOT NULL UNIQUE,
                encrypted_metadata BLOB NOT NULL,
                metadata_iv BLOB NOT NULL,
                created_at INTEGER NOT NULL
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id TEXT NOT NULL UNIQUE,
                project_id INTEGER NOT NULL,
                encrypted_metadata BLOB NOT NULL,
                metadata_iv BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id TEXT NOT NULL UNIQUE,
                service_id INTEGER NOT NULL,
                encrypted_metadata BLOB NOT NULL,
                metadata_iv BLOB NOT NULL,
                encrypted_value BLOB NOT NULL,
                iv BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
            )
            """.trimIndent()
        )
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_services_project ON services(project_id)")
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_secrets_service ON secrets(service_id)")
    }

    private fun metadataAad(type: String, recordId: String): String =
        "keybooks:metadata:$type:$recordId"

    companion object {
        private const val DATABASE_NAME = "keybooks.db"
        private const val DATABASE_VERSION = 2
        private const val TYPE_PROJECT = "project"
        private const val TYPE_SERVICE = "service"
        private const val TYPE_SECRET = "secret"
    }
}
