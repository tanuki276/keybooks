package com.tanuki276.keybooks.ui

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.tanuki276.keybooks.R
import com.tanuki276.keybooks.data.*
import com.tanuki276.keybooks.security.BiometricGate
import com.tanuki276.keybooks.security.CryptoManager
import com.tanuki276.keybooks.settings.AppPreferences
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun KeybooksApp(
    database: KeybooksDatabase,
    cryptoManager: CryptoManager,
    biometricGate: BiometricGate,
    appPreferences: AppPreferences,
    maskEpoch: Int
) {
    val scope = rememberCoroutineScope()
    var project by remember { mutableStateOf<ProjectItem?>(null) }
    var projects by remember { mutableStateOf(emptyList<ProjectItem>()) }
    var services by remember { mutableStateOf(emptyList<ServiceBundle>()) }
    var refresh by remember { mutableIntStateOf(0) }
    var settingsOpen by remember { mutableStateOf(false) }
    var clipboardClearSeconds by remember { mutableStateOf(appPreferences.clipboardClearSeconds) }

    LaunchedEffect(project?.id, refresh) {
        if (project == null) {
            projects = withContext(Dispatchers.IO) { database.getProjects() }
        } else {
            services = withContext(Dispatchers.IO) { database.getProjectServices(project!!.id) }
        }
    }

    if (project == null) {
        ProjectList(
            projects = projects,
            onOpen = { project = it },
            onSettings = { settingsOpen = true },
            onCreate = { name ->
                scope.launch {
                    withContext(Dispatchers.IO) { database.insertProject(name) }
                    refresh++
                }
            }
        )
    } else {
        BackHandler { project = null }
        ProjectScreen(
            project = project!!,
            services = services,
            cryptoManager = cryptoManager,
            biometricGate = biometricGate,
            clipboardClearSeconds = clipboardClearSeconds,
            maskEpoch = maskEpoch,
            onBack = { project = null },
            onSettings = { settingsOpen = true },
            onCreateService = { name ->
                scope.launch {
                    withContext(Dispatchers.IO) { database.insertService(project!!.id, name) }
                    refresh++
                }
            },
            onCreateSecret = { serviceId, draft, done, fail ->
                fun save(payload: com.tanuki276.keybooks.security.EncryptedPayload) {
                    scope.launch {
                        withContext(Dispatchers.IO) {
                            database.insertSecret(
                                serviceId = serviceId,
                                name = draft.name,
                                encryptedValue = payload.encryptedValue,
                                iv = payload.iv,
                                hidden = draft.hidden,
                                authType = draft.authType,
                                passwordSalt = payload.passwordSalt
                            )
                        }
                        refresh++
                        done()
                    }
                }

                try {
                    when (draft.authType) {
                        AuthType.NONE -> save(cryptoManager.encryptWithoutAuthentication(draft.value))
                        AuthType.PASSWORD -> save(cryptoManager.encryptWithPassword(draft.value, draft.password))
                        AuthType.BIOMETRIC -> {
                            val cipher = cryptoManager.newBiometricEncryptCipher()
                            biometricGate.authenticate(
                                cipher = cipher,
                                title = "${draft.name} を保存",
                                onSuccess = { authenticated ->
                                    runCatching { cryptoManager.encryptWithAuthenticatedCipher(authenticated, draft.value) }
                                        .onSuccess(::save)
                                        .onFailure { fail(it.message ?: "暗号化に失敗しました") }
                                },
                                onError = fail
                            )
                        }
                    }
                } catch (e: Exception) {
                    fail(e.message ?: "保存に失敗しました")
                }
            }
        )
    }

    if (settingsOpen) {
        SettingsDialog(
            currentSeconds = clipboardClearSeconds,
            onDismiss = { settingsOpen = false },
            onSave = { seconds ->
                appPreferences.clipboardClearSeconds = seconds
                clipboardClearSeconds = seconds
                settingsOpen = false
            }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ProjectList(
    projects: List<ProjectItem>,
    onOpen: (ProjectItem) -> Unit,
    onSettings: () -> Unit,
    onCreate: (String) -> Unit
) {
    var dialog by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Keybooks") },
                actions = {
                    IconButton(onClick = onSettings) {
                        VectorIcon(R.drawable.ic_settings, "設定")
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { dialog = true }) {
                VectorIcon(R.drawable.ic_add, "プロジェクト追加")
            }
        }
    ) { padding ->
        if (projects.isEmpty()) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Text("＋ から最初のプロジェクトを作成")
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(projects, key = { it.id }) { item ->
                    Card(
                        onClick = { onOpen(item) },
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)
                    ) {
                        Text(item.name, modifier = Modifier.padding(20.dp), style = MaterialTheme.typography.titleMedium)
                    }
                }
                item { Spacer(Modifier.height(80.dp)) }
            }
        }
    }

    if (dialog) {
        TextInputDialog(
            title = "プロジェクトを作成",
            label = "プロジェクト名",
            onDismiss = { dialog = false },
            onSave = { onCreate(it); dialog = false }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ProjectScreen(
    project: ProjectItem,
    services: List<ServiceBundle>,
    cryptoManager: CryptoManager,
    biometricGate: BiometricGate,
    clipboardClearSeconds: Long?,
    maskEpoch: Int,
    onBack: () -> Unit,
    onSettings: () -> Unit,
    onCreateService: (String) -> Unit,
    onCreateSecret: (Long, SecretDraft, () -> Unit, (String) -> Unit) -> Unit
) {
    var serviceDialog by remember { mutableStateOf(false) }
    var selectedServiceId by remember { mutableStateOf<Long?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(project.name) },
                navigationIcon = {
                    IconButton(onClick = onBack) { VectorIcon(R.drawable.ic_back, "戻る") }
                },
                actions = {
                    IconButton(onClick = onSettings) { VectorIcon(R.drawable.ic_settings, "設定") }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { serviceDialog = true }) {
                VectorIcon(R.drawable.ic_add, "サービス追加")
            }
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            items(services, key = { it.service.id }) { bundle ->
                Card(Modifier.fillMaxWidth()) {
                    Row(
                        Modifier.fillMaxWidth().padding(start = 16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(bundle.service.name, modifier = Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
                        IconButton(onClick = { selectedServiceId = bundle.service.id }) {
                            VectorIcon(R.drawable.ic_add, "機密情報追加")
                        }
                    }
                    bundle.secrets.forEach { secret ->
                        HorizontalDivider()
                        SecretRow(
                            secret = secret,
                            cryptoManager = cryptoManager,
                            biometricGate = biometricGate,
                            clipboardClearSeconds = clipboardClearSeconds,
                            maskEpoch = maskEpoch
                        )
                    }
                    if (bundle.secrets.isEmpty()) {
                        Text("機密情報はまだありません", modifier = Modifier.padding(16.dp))
                    }
                }
            }
            item { Spacer(Modifier.height(80.dp)) }
        }
    }

    if (serviceDialog) {
        TextInputDialog(
            title = "サービスを追加",
            label = "サービス / ツール名",
            onDismiss = { serviceDialog = false },
            onSave = { onCreateService(it); serviceDialog = false }
        )
    }

    selectedServiceId?.let { serviceId ->
        SecretDialog(
            onDismiss = { selectedServiceId = null },
            onSave = { draft, fail -> onCreateSecret(serviceId, draft, { selectedServiceId = null }, fail) }
        )
    }
}

@Composable
private fun SecretRow(
    secret: SecretItem,
    cryptoManager: CryptoManager,
    biometricGate: BiometricGate,
    clipboardClearSeconds: Long?,
    maskEpoch: Int
) {
    val context = LocalContext.current
    var value by remember(secret.id) { mutableStateOf<String?>(null) }
    var passwordDialog by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(value) {
        if (value != null) {
            delay(30_000)
            value = null
        }
    }
    LaunchedEffect(maskEpoch) { value = null }

    fun reveal() {
        error = null
        when (secret.authType) {
            AuthType.NONE -> runCatching {
                cryptoManager.decryptWithoutAuthentication(secret.encryptedValue, secret.iv)
            }.onSuccess { value = it }.onFailure { error = "復号に失敗しました" }

            AuthType.PASSWORD -> passwordDialog = true

            AuthType.BIOMETRIC -> runCatching {
                cryptoManager.newBiometricDecryptCipher(secret.iv)
            }.onSuccess { cipher ->
                biometricGate.authenticate(
                    cipher = cipher,
                    title = secret.name,
                    onSuccess = { authenticated ->
                        runCatching { cryptoManager.decryptWithAuthenticatedCipher(authenticated, secret.encryptedValue) }
                            .onSuccess { value = it }
                            .onFailure { error = "復号に失敗しました" }
                    },
                    onError = { error = it }
                )
            }.onFailure { error = "生体認証キーを利用できません" }
        }
    }

    Column(Modifier.fillMaxWidth().padding(16.dp)) {
        Text(secret.name, style = MaterialTheme.typography.labelLarge)
        Spacer(Modifier.height(4.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                value ?: "••••••••••••",
                modifier = Modifier.weight(1f),
                fontFamily = FontFamily.Monospace
            )
            IconButton(onClick = { reveal() }) { VectorIcon(R.drawable.ic_visibility, "表示") }
            IconButton(onClick = {
                if (value == null) reveal() else copySensitive(context, value!!, clipboardClearSeconds)
            }) { VectorIcon(R.drawable.ic_copy, "コピー") }
        }
        Text(
            when (secret.authType) {
                AuthType.NONE -> "認証: なし"
                AuthType.BIOMETRIC -> "認証: 生体認証"
                AuthType.PASSWORD -> "認証: パスワード"
            },
            style = MaterialTheme.typography.bodySmall
        )
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    }

    if (passwordDialog) {
        PasswordDialog(
            onDismiss = { passwordDialog = false },
            onSubmit = { password, wrong ->
                val salt = secret.passwordSalt ?: return@PasswordDialog
                runCatching {
                    cryptoManager.decryptWithPassword(secret.encryptedValue, secret.iv, salt, password)
                }.onSuccess {
                    value = it
                    passwordDialog = false
                }.onFailure { wrong() }
            }
        )
    }
}

@Composable
private fun VectorIcon(drawableRes: Int, description: String) {
    Icon(
        painter = painterResource(drawableRes),
        contentDescription = description,
        tint = LocalContentColor.current
    )
}

@Composable
private fun SettingsDialog(
    currentSeconds: Long?,
    onDismiss: () -> Unit,
    onSave: (Long?) -> Unit
) {
    var unlimited by remember { mutableStateOf(currentSeconds == null) }
    var secondsText by remember { mutableStateOf((currentSeconds ?: 30L).toString()) }
    val seconds = secondsText.toLongOrNull()
    val valid = unlimited || (seconds != null && seconds >= 1L)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("設定") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("クリップボード自動消去")
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = unlimited, onCheckedChange = { unlimited = it })
                    Spacer(Modifier.width(8.dp))
                    Text("無期限（自動消去しない）")
                }
                OutlinedTextField(
                    value = secondsText,
                    onValueChange = { secondsText = it.filter(Char::isDigit) },
                    enabled = !unlimited,
                    singleLine = true,
                    label = { Text("消去までの秒数") },
                    supportingText = { Text("1秒以上の任意の値") }
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onSave(if (unlimited) null else seconds) },
                enabled = valid
            ) { Text("保存") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("キャンセル") } }
    )
}

@Composable
private fun TextInputDialog(
    title: String,
    label: String,
    onDismiss: () -> Unit,
    onSave: (String) -> Unit
) {
    var text by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { OutlinedTextField(text, { text = it }, label = { Text(label) }, singleLine = true) },
        confirmButton = { Button(onClick = { onSave(text.trim()) }, enabled = text.isNotBlank()) { Text("保存") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("キャンセル") } }
    )
}

private data class SecretDraft(
    val name: String,
    val value: String,
    val hidden: Boolean,
    val authType: AuthType,
    val password: String
)

@Composable
private fun SecretDialog(
    onDismiss: () -> Unit,
    onSave: (SecretDraft, (String) -> Unit) -> Unit
) {
    var name by remember { mutableStateOf("") }
    var value by remember { mutableStateOf("") }
    var hidden by remember { mutableStateOf(true) }
    var auth by remember { mutableStateOf(AuthType.NONE) }
    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("機密情報を追加") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(name, { name = it }, label = { Text("名前") }, placeholder = { Text("GITHUB_TOKEN") })
                OutlinedTextField(
                    value,
                    { value = it },
                    label = { Text("キー / 値") },
                    placeholder = { Text("ghp_••••••••") },
                    visualTransformation = if (hidden) PasswordVisualTransformation() else VisualTransformation.None
                )
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text("隠しますか？", modifier = Modifier.weight(1f))
                    Switch(hidden, { hidden = it })
                }
                Text("認証方法")
                AuthOption("なし", AuthType.NONE, auth) { auth = it }
                AuthOption("生体認証", AuthType.BIOMETRIC, auth) { auth = it }
                AuthOption("パスワード", AuthType.PASSWORD, auth) { auth = it }
                if (auth == AuthType.PASSWORD) {
                    OutlinedTextField(
                        password,
                        { password = it },
                        label = { Text("任意パスワード") },
                        visualTransformation = PasswordVisualTransformation()
                    )
                }
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            Button(
                onClick = { onSave(SecretDraft(name.trim(), value, hidden, auth, password)) { error = it } },
                enabled = name.isNotBlank() && value.isNotBlank() && (auth != AuthType.PASSWORD || password.isNotBlank())
            ) { Text("保存") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("キャンセル") } }
    )
}

@Composable
private fun AuthOption(label: String, type: AuthType, selected: AuthType, onChange: (AuthType) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        RadioButton(selected == type, onClick = { onChange(type) })
        Text(label)
    }
}

@Composable
private fun PasswordDialog(onDismiss: () -> Unit, onSubmit: (String, () -> Unit) -> Unit) {
    var password by remember { mutableStateOf("") }
    var wrong by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("パスワード認証") },
        text = {
            Column {
                OutlinedTextField(
                    password,
                    { password = it; wrong = false },
                    label = { Text("パスワード") },
                    visualTransformation = PasswordVisualTransformation()
                )
                if (wrong) Text("パスワードが違います", color = MaterialTheme.colorScheme.error)
            }
        },
        confirmButton = { Button(onClick = { onSubmit(password) { wrong = true } }, enabled = password.isNotBlank()) { Text("解除") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("キャンセル") } }
    )
}

private fun copySensitive(context: Context, value: String, clearAfterSeconds: Long?) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val token = UUID.randomUUID().toString()
    val clip = ClipData.newPlainText("Keybooks secret", value)
    clip.description.extras = PersistableBundle().apply {
        putString(CLIP_TOKEN_KEY, token)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
    }
    clipboard.setPrimaryClip(clip)

    if (clearAfterSeconds != null) {
        val delayMillis = clearAfterSeconds.coerceAtMost(MAX_CLIPBOARD_SECONDS) * 1_000L
        Handler(Looper.getMainLooper()).postDelayed({
            val currentToken = clipboard.primaryClipDescription?.extras?.getString(CLIP_TOKEN_KEY)
            if (currentToken == token) clipboard.clearPrimaryClip()
        }, delayMillis)
    }
}

private const val CLIP_TOKEN_KEY = "com.tanuki276.keybooks.CLIP_TOKEN"
private const val MAX_CLIPBOARD_SECONDS = 31_536_000L
