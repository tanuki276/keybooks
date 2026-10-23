package com.tanuki276.keybooks

import androidx.test.platform.app.InstrumentationRegistry
import com.tanuki276.keybooks.data.*
import com.tanuki276.keybooks.security.CryptoManager
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.Assert.*

class DatabaseSecurityTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var database: KeybooksDatabase
    private lateinit var crypto: CryptoManager
    @Before fun setup() {
        context.deleteDatabase("keybooks.db")
        crypto = CryptoManager()
        database = KeybooksDatabase(context, crypto)
    }
    @After fun cleanup() { database.close(); context.deleteDatabase("keybooks.db") }
    private fun seed(): Long {
        val project = database.insertProject("Private project")
        val service = database.insertService(project, "Private service")
        val payload = crypto.encryptWithoutAuthentication("private value")
        database.insertSecret(service, "Private secret", payload.encryptedValue, payload.iv, true, AuthType.NONE, null)
        return project
    }
    @Test fun crudAndCascade() {
        val project = seed()
        database.rename("projects", project, "Renamed")
        assertEquals("Renamed", database.getProjects().single().name)
        val secret = database.getProjectServices(project).single().secrets.single()
        database.replaceSecret(secret.id, secret.serviceId, "Edited", crypto.encryptWithoutAuthentication("new value"), true, AuthType.NONE)
        val edited = database.getProjectServices(project).single().secrets.single()
        assertEquals("new value", crypto.decryptWithoutAuthentication(edited.encryptedValue, edited.iv))
        database.delete("projects", project)
        assertTrue(database.getProjects().isEmpty())
        database.readableDatabase.rawQuery("SELECT COUNT(*) FROM secrets", null).use { it.moveToFirst(); assertEquals(0, it.getInt(0)) }
    }
    @Test fun metadataAndValueTamperingFailClosed() {
        val project = seed()
        database.writableDatabase.execSQL("UPDATE secrets SET encrypted_value = zeroblob(length(encrypted_value))")
        assertFalse(database.getProjectServices(project).single().secrets.single().readable)
        database.writableDatabase.execSQL("UPDATE projects SET encrypted_metadata = zeroblob(length(encrypted_metadata))")
        assertFalse(database.getProjects().single().readable)
    }
    @Test fun importValidatesBeforeWritingAndMerges() {
        seed()
        val valid = """{"version":1,"projects":[{"name":"restored","services":[{"name":"service","secrets":[{"name":"token","value":"value","hidden":true}]}]}]}"""
        database.importPortable(valid, "long backup password")
        assertEquals(2, database.getProjects().size)
        val restored = database.getProjects().first { it.name == "restored" }
        val secret = database.getProjectServices(restored.id).single().secrets.single()
        assertEquals(AuthType.PASSWORD, secret.authType)
        assertEquals("value", crypto.decryptWithPassword(secret.encryptedValue, secret.iv, secret.passwordSalt!!, "long backup password"))
        try { database.importPortable(valid.replace("\"hidden\":true", "\"wrong\":true"), "long backup password"); fail("Invalid import accepted") }
        catch (_: org.json.JSONException) { }
        assertEquals(2, database.getProjects().size)
    }
    @Test fun recoveryPayloadSurvivesAndCancelledImportRollsBack() {
        val project = database.insertProject("project")
        val service = database.insertService(project, "service")
        val recovery = crypto.encryptWithPassword("recoverable", "long recovery password")
        val primary = crypto.encryptWithoutAuthentication("recoverable")
        database.insertSecret(service, "secret", primary.encryptedValue, primary.iv,
            true, AuthType.BIOMETRIC, null, recovery)
        val restoredRecovery = database.getProjectServices(project).single().secrets.single().recovery!!
        assertEquals("recoverable", crypto.decryptWithPassword(restoredRecovery.encryptedValue,
            restoredRecovery.iv, restoredRecovery.passwordSalt!!, "long recovery password"))
        var checks = 0
        try {
            database.importPortable("""{"version":1,"projects":[{"name":"cancelled","services":[]}]}""", "backup password") {
                checks++
                if (checks == 3) throw java.util.concurrent.CancellationException()
            }
            fail("Import should cancel before commit")
        } catch (_: java.util.concurrent.CancellationException) { }
        assertEquals(1, database.getProjects().size)
    }

    @Test fun damagedOldRecordDoesNotHideRestoredData() {
        seed()
        database.writableDatabase.execSQL("UPDATE projects SET encrypted_metadata = zeroblob(length(encrypted_metadata))")
        database.importPortable("""{"version":1,"projects":[{"name":"restored","services":[]}]}""", "backup password")
        val projects = database.getProjects()
        assertEquals(2, projects.size)
        assertTrue(projects.single { it.name == "restored" }.readable)
        assertEquals(1, projects.count { !it.readable })
    }

}
