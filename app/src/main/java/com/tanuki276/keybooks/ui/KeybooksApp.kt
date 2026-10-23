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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.tanuki276.keybooks.data.*
import com.tanuki276.keybooks.security.BiometricGate
import com.tanuki276.keybooks.security.CryptoManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun KeybooksApp(
    database: KeybooksDatabase,
    cryptoManager: CryptoManager,
    biometricGate: BiometricGate
) {
    val scope = rememberCoroutineScope()
    var project by remember { mutableStateOf<ProjectItem?>(null) }
    var projects by remember { mutableStateOf(emptyList<ProjectItem>()) }
    var services by remember { mutableStateOf(emptyList<ServiceBundle>()) }
    var refresh by remember { mutableIntStateOf(0) }

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
            onBack = { project = null },
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
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ProjectList(
    projects: List<ProjectItem>,
    onOpen: (ProjectItem) -> Unit,
    onCreate: (String) -> Unit
) {
    var dialog by remember { mutableStateOf(false) }

    Scaffold(
        topBar = { TopAppBar(title = { Text("Keybooks") }) },
        floatingActionButton = {
            FloatingActionButton(onClick = { dialog = true }) {
                Icon(Icons.Default.Add, contentDescription = "プロジェクト追加")
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
    onBack: () -> Unit,
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
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "戻る")
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { serviceDialog = true }) {
                Icon(Icons.Default.Add, contentDescription = "サービス追加")
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
                            Icon(Icons.Default.Add, contentDescription = "機密情報追加")
                        }
                    }
                    bundle.secrets.forEach { secret ->
                        HorizontalDivider()
                        SecretRow(secret, cryptoManager, biometricGate)
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
            onSave = { draft, fail ->
                onCreateSecret(serviceId, draft, { selectedServiceId = null }, fail)
            }
        )
    }
}

@Composable
private fun SecretRow(
    secret: SecretItem,
    cryptoManager: CryptoManager,
    biometricGate: BiometricGate
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
            IconButton(onClick = { reveal() }) {
                Icon(Icons.Default.Visibility, contentDescription = "表示")
            }
            IconButton(onClick = {
                if (value == null) {
                    reveal()
                } else {
                    copySensitive(context, value!!)
                }
            }) {
                Icon(Icons.Default.ContentCopy, contentDescription = "コピー")
            }
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
        confirmButton = {
            Button(onClick = { onSave(text.trim()) }, enabled = text.isNotBlank()) { Text("保存") }
        },
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
                    visualTransformation = if (hidden) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None
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
                onClick = {
                    onSave(SecretDraft(name.trim(), value, hidden, auth, password)) { error = it }
                },
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
        confirmButton = {
            Button(onClick = { onSubmit(password) { wrong = true } }, enabled = password.isNotBlank()) { Text("解除") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("キャンセル") } }
    )
}

private fun copySensitive(context: Context, value: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clip = ClipData.newPlainText("Keybooks secret", value)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        clip.description.extras = PersistableBundle().apply {
            putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
    }
    clipboard.setPrimaryClip(clip)
    Handler(Looper.getMainLooper()).postDelayed({
        val current = clipboard.primaryClip?.getItemAt(0)?.coerceToText(context)?.toString()
        if (current == value) clipboard.clearPrimaryClip()
    }, 30_000)
}
