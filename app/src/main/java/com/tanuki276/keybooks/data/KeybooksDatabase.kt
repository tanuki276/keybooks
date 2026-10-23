package com.tanuki276.keybooks.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

class KeybooksDatabase(context: Context) : SQLiteOpenHelper(
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
        db.execSQL(
            """
            CREATE TABLE projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            )
            """.trimIndent()
        )
        db.execSQL(
            """
            CREATE TABLE secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                encrypted_value BLOB NOT NULL,
                iv BLOB NOT NULL,
                hidden INTEGER NOT NULL,
                auth_type TEXT NOT NULL,
                password_salt BLOB,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
            )
            """.trimIndent()
        )
        db.execSQL("CREATE INDEX idx_services_project ON services(project_id)")
        db.execSQL("CREATE INDEX idx_secrets_service ON secrets(service_id)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit

    fun insertProject(name: String): Long {
        val values = ContentValues().apply {
            put("name", name.trim())
            put("created_at", System.currentTimeMillis())
        }
        return writableDatabase.insertOrThrow("projects", null, values)
    }

    fun insertService(projectId: Long, name: String): Long {
        val values = ContentValues().apply {
            put("project_id", projectId)
            put("name", name.trim())
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
        passwordSalt: ByteArray?
    ): Long {
        val values = ContentValues().apply {
            put("service_id", serviceId)
            put("name", name.trim())
            put("encrypted_value", encryptedValue)
            put("iv", iv)
            put("hidden", if (hidden) 1 else 0)
            put("auth_type", authType.name)
            if (passwordSalt != null) put("password_salt", passwordSalt) else putNull("password_salt")
            put("created_at", System.currentTimeMillis())
        }
        return writableDatabase.insertOrThrow("secrets", null, values)
    }

    fun getProjects(): List<ProjectItem> {
        val result = mutableListOf<ProjectItem>()
        readableDatabase.query(
            "projects",
            arrayOf("id", "name", "created_at"),
            null, null, null, null,
            "created_at DESC"
        ).use { cursor ->
            while (cursor.moveToNext()) {
                result += ProjectItem(cursor.getLong(0), cursor.getString(1), cursor.getLong(2))
            }
        }
        return result
    }

    fun getProjectServices(projectId: Long): List<ServiceBundle> {
        val services = mutableListOf<ServiceItem>()
        readableDatabase.query(
            "services",
            arrayOf("id", "project_id", "name", "created_at"),
            "project_id = ?",
            arrayOf(projectId.toString()),
            null, null,
            "created_at ASC"
        ).use { cursor ->
            while (cursor.moveToNext()) {
                services += ServiceItem(
                    id = cursor.getLong(0),
                    projectId = cursor.getLong(1),
                    name = cursor.getString(2),
                    createdAt = cursor.getLong(3)
                )
            }
        }
        return services.map { ServiceBundle(it, getSecrets(it.id)) }
    }

    private fun getSecrets(serviceId: Long): List<SecretItem> {
        val result = mutableListOf<SecretItem>()
        readableDatabase.query(
            "secrets",
            arrayOf("id", "service_id", "name", "encrypted_value", "iv", "hidden", "auth_type", "password_salt", "created_at"),
            "service_id = ?",
            arrayOf(serviceId.toString()),
            null, null,
            "created_at ASC"
        ).use { cursor ->
            while (cursor.moveToNext()) {
                result += SecretItem(
                    id = cursor.getLong(0),
                    serviceId = cursor.getLong(1),
                    name = cursor.getString(2),
                    encryptedValue = cursor.getBlob(3),
                    iv = cursor.getBlob(4),
                    hidden = cursor.getInt(5) == 1,
                    authType = AuthType.valueOf(cursor.getString(6)),
                    passwordSalt = if (cursor.isNull(7)) null else cursor.getBlob(7),
                    createdAt = cursor.getLong(8)
                )
            }
        }
        return result
    }

    companion object {
        private const val DATABASE_NAME = "keybooks.db"
        private const val DATABASE_VERSION = 1
    }
}
