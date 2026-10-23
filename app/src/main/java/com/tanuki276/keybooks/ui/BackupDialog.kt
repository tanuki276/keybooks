package com.tanuki276.keybooks.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.tanuki276.keybooks.data.*
import com.tanuki276.keybooks.security.*
import kotlinx.coroutines.*
import org.json.JSONArray
import org.json.JSONObject

@Composable
internal fun BackupDialog(database: KeybooksDatabase, crypto: CryptoManager, biometric: BiometricGate,
    maskEpoch: Int, onDismiss: () -> Unit, onImported: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var pendingBytes by remember { mutableStateOf<ByteArray?>(null) }
    var passwordRequest by remember { mutableStateOf<Pair<String, CompletableDeferred<String?>>?>(null) }
    var entryPassword by remember { mutableStateOf("") }
    var operation by remember { mutableStateOf<Job?>(null) }

    DisposableEffect(Unit) {
        onDispose { pendingBytes?.fill(0); passwordRequest?.second?.complete(null); operation?.cancel() }
    }
    LaunchedEffect(maskEpoch) {
        password = ""; confirmation = ""; entryPassword = ""
        passwordRequest?.second?.complete(null); passwordRequest = null
        // A document picker also backgrounds the activity. Keep only the encrypted export bytes.
        operation?.cancel(); busy = false
    }

    val exportFile = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val bytes = pendingBytes
        pendingBytes = null
        if (uri == null || bytes == null) { bytes?.fill(0); message = "Exportをキャンセルしました" }
        else {
            scope.launch {
                busy = true
                try {
                    withContext(Dispatchers.IO) {
                        val stream = context.contentResolver.openOutputStream(uri, "wt") ?: error("出力先を開けません")
                        stream.use { it.write(bytes); it.flush() }
                    }
                    message = "Exportしました。ファイルを別の端末や安全な保存先にも保管し、Importで検証してください。"
                } catch (_: Exception) { message = "保存できませんでした。出力先の不完全なファイルを削除して再試行してください。" }
                finally { bytes.fill(0); busy = false }
            }
        }
    }
    // File selection happens before the password is entered; no password survives backgrounding.
    var importUri by remember { mutableStateOf<android.net.Uri?>(null) }
    val importFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        importUri = uri
        message = if (uri == null) "Importをキャンセルしました" else "ファイルを選択しました。バックアップのパスワードを入力して復元してください。"
    }

    suspend fun unlock(secret: SecretItem): String {
        return when (secret.authType) {
            AuthType.NONE -> withContext(Dispatchers.IO) { crypto.decryptWithoutAuthentication(secret.encryptedValue, secret.iv) }
            AuthType.PASSWORD -> {
                val answer = CompletableDeferred<String?>()
                entryPassword = ""; passwordRequest = secret.name to answer
                val supplied = answer.await() ?: throw CancellationException()
                passwordRequest = null; entryPassword = ""
                withContext(Dispatchers.IO) {
                    crypto.decryptWithPassword(secret.encryptedValue, secret.iv, requireNotNull(secret.passwordSalt), supplied)
                }
            }
            AuthType.BIOMETRIC -> {
                val answer = CompletableDeferred<String>()
                biometric.authenticate(crypto.newBiometricDecryptCipher(secret.iv, Envelope.isEnvelope(secret.encryptedValue)), "${secret.name} をExport",
                    onSuccess = { cipher ->
                        try { answer.complete(crypto.decryptWithAuthenticatedCipher(cipher, secret.encryptedValue)) }
                        catch (e: Exception) { answer.completeExceptionally(e) }
                    }, onError = { answer.completeExceptionally(IllegalStateException(it)) })
                answer.await()
            }
        }
    }

    AlertDialog(onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("暗号化Export / Import") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Exportには全項目の認証が必要です。鍵が失われる前に実行し、ファイルを端末外に保存してください。")
                Text("Importは既存データに追加します。復元した全項目はバックアップのパスワードで保護されます。復元後に編集で認証方式を変更できます。")
                OutlinedTextField(password, { password = it }, enabled = !busy, singleLine = true,
                    label = { Text("バックアップのパスワード") }, visualTransformation = PasswordVisualTransformation())
                PasswordStrength.warning(password)?.let { Text(it) }
                OutlinedTextField(confirmation, { confirmation = it }, enabled = !busy, singleLine = true,
                    label = { Text("Export用の確認入力") }, visualTransformation = PasswordVisualTransformation())
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                TextButton(enabled = !busy, onClick = { importFile.launch(arrayOf("*/*")) }) { Text("Importファイルを選択") }
                if (importUri != null) Button(enabled = !busy && password.isNotEmpty(), onClick = {
                    val uri = importUri!!
                    val supplied = password
                    busy = true; message = null
                    operation = scope.launch {
                        try {
                            withContext(Dispatchers.IO) {
                                val bytes = context.contentResolver.openInputStream(uri)?.use {
                                    val output = java.io.ByteArrayOutputStream()
                                    val buffer = ByteArray(8192)
                                    while (true) {
                                        val count = it.read(buffer)
                                        if (count == -1) break
                                        require(output.size() + count <= PortableCrypto.MAX_BYTES) { "File too large" }
                                        output.write(buffer, 0, count)
                                    }
                                    output.toByteArray()
                                } ?: error("ファイルを開けません")
                                val plaintext = try { PortableCrypto.open(bytes, supplied) } finally { bytes.fill(0) }
                                try { database.importPortable(plaintext.toString(Charsets.UTF_8), supplied) }
                                finally { plaintext.fill(0) }
                            }
                            password = ""; confirmation = ""; importUri = null
                            onImported(); message = "復元しました。既存データは保持されています。"
                        } catch (e: CancellationException) { throw e }
                        catch (_: Exception) { message = "復元できません。パスワード、ファイルの破損、空き容量を確認してください。既存データは保持されています。" }
                        finally { busy = false }
                    }
                }) { Text("追加して復元") }
                message?.let { Text(it) }
            }
        },
        confirmButton = { Button(enabled = !busy && password.length >= 12 && password == confirmation, onClick = {
            val supplied = password
            busy = true; message = null
            operation = scope.launch {
                try {
                    val projects = withContext(Dispatchers.IO) { database.getProjects() }
                    val root = JSONObject().put("version", 1)
                    val array = JSONArray()
                    for (project in projects) {
                        check(project.readable) { "Unreadable project" }
                        val services = withContext(Dispatchers.IO) { database.getProjectServices(project.id) }
                        val serviceArray = JSONArray()
                        for (bundle in services) {
                            check(bundle.service.readable) { "Unreadable service" }
                            val secrets = JSONArray()
                            for (secret in bundle.secrets) {
                                check(secret.readable) { "Unreadable secret" }
                                secrets.put(JSONObject().put("name", secret.name).put("hidden", secret.hidden)
                                    .put("value", unlock(secret)))
                            }
                            serviceArray.put(JSONObject().put("name", bundle.service.name).put("secrets", secrets))
                        }
                        array.put(JSONObject().put("name", project.name).put("services", serviceArray))
                    }
                    root.put("projects", array)
                    val plain = root.toString().toByteArray(Charsets.UTF_8)
                    pendingBytes = try { withContext(Dispatchers.Default) { PortableCrypto.seal(plain, supplied) } }
                        finally { plain.fill(0) }
                    password = ""; confirmation = ""
                    exportFile.launch("keybooks-backup.kbb")
                } catch (e: CancellationException) { message = "Exportをキャンセルしました"; throw e }
                catch (_: Exception) { message = "Exportできません。全項目のパスワード・生体認証と保存データを確認してください。鍵を失った項目は復号できません。" }
                finally { passwordRequest = null; entryPassword = ""; busy = false }
            }
        }) { Text("Export") } },
        dismissButton = { TextButton(onClick = { operation?.cancel(); onDismiss() }) { Text(if (busy) "中止" else "閉じる") } })

    passwordRequest?.let { request ->
        AlertDialog(onDismissRequest = { request.second.complete(null) }, title = { Text("${request.first} の認証") },
            text = { OutlinedTextField(entryPassword, { entryPassword = it }, visualTransformation = PasswordVisualTransformation(), singleLine = true) },
            confirmButton = { TextButton(onClick = { request.second.complete(entryPassword) }, enabled = entryPassword.isNotEmpty()) { Text("解除") } },
            dismissButton = { TextButton(onClick = { request.second.complete(null) }) { Text("中止") } })
    }
}
