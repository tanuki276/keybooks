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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
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
import com.tanuki276.keybooks.security.PasswordStrength
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
    var backupOpen by remember { mutableStateOf(false) }
    var appError by remember { mutableStateOf<String?>(null) }
    fun mutate(action: () -> Unit) {
        scope.launch {
            try { withContext(Dispatchers.IO) { action() }; refresh++ }
            catch (_: Exception) { appError = "保存できませんでした。空き容量を確認して再試行してください。データは削除しないでください。" }
        }
    }
    var settingsOpen by remember { mutableStateOf(false) }
    var clipboardClearSeconds by remember { mutableStateOf(appPreferences.clipboardClearSeconds) }

    LaunchedEffect(project?.id, refresh) {
        try {
            val selected = project
            if (selected == null) projects = withContext(Dispatchers.IO) { database.getProjects() }
            else services = withContext(Dispatchers.IO) { database.getProjectServices(selected.id) }
        } catch (_: Exception) {
            projects = emptyList(); services = emptyList()
            appError = "データを読み込めません。鍵の消失またはデータ破損の可能性があります。アンインストールせず、設定の暗号化バックアップから復元してください。"
        }
    }

    if (project == null) {
        ProjectList(
            projects = projects,
            onManage = { id, name -> mutate { if (name == null) database.delete("projects", id) else database.rename("projects", id, name) } },
            onOpen = { project = it },
            onSettings = { settingsOpen = true },
            onCreate = { name ->
                mutate { database.insertProject(name) }
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
            onManage = { table, id, name -> mutate { if (name == null) database.delete(table, id) else database.rename(table, id, name) } },
            onCreateService = { name ->
                val id = project!!.id
                mutate { database.insertService(id, name) }
            },
            onCreateSecret = { serviceId, draft, done, fail ->
                fun save(payload: com.tanuki276.keybooks.security.EncryptedPayload) {
                    scope.launch {
                        try {
                        withContext(Dispatchers.IO) {
                            val recovery = if (draft.authType == AuthType.BIOMETRIC)
                                cryptoManager.encryptWithPassword(draft.value, draft.password) else null
                            if (draft.id != null) database.replaceSecret(draft.id, serviceId, draft.name, payload, draft.hidden, draft.authType, recovery)
                            else database.insertSecret(
                                serviceId = serviceId,
                                name = draft.name,
                                encryptedValue = payload.encryptedValue,
                                iv = payload.iv,
                                hidden = draft.hidden,
                                authType = draft.authType,
                                passwordSalt = payload.passwordSalt,
                                recovery = recovery
                            )
                        }
                        refresh++
                        done()
                        } catch (_: Exception) { fail("保存できませんでした。空き容量を確認して再試行してください") }
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
            onBackup = { settingsOpen = false; backupOpen = true },
            currentSeconds = clipboardClearSeconds,
            onDismiss = { settingsOpen = false },
            onSave = { seconds ->
                appPreferences.clipboardClearSeconds = seconds
                clipboardClearSeconds = seconds
                settingsOpen = false
            }
        )
    }
    if (backupOpen) BackupDialog(database, cryptoManager, biometricGate, maskEpoch,
        onDismiss = { backupOpen = false }, onImported = { project = null; refresh++ })
    appError?.let { message -> AlertDialog(onDismissRequest = { appError = null },
        title = { Text("データの復旧") }, text = { Text(message) },
        confirmButton = { TextButton(onClick = { appError = null; backupOpen = true }) { Text("バックアップを復元") } },
        dismissButton = { TextButton(onClick = { appError = null; refresh++ }) { Text("再試行") } }) }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ProjectList(
    projects: List<ProjectItem>,
    onManage: (Long, String?) -> Unit,
    onOpen: (ProjectItem) -> Unit,
    onSettings: () -> Unit,
    onCreate: (String) -> Unit
) {
    var query by remember { mutableStateOf("") }
    var alphabetical by remember { mutableStateOf(false) }
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
                item { SearchSort(query, { query = it }, alphabetical, { alphabetical = !alphabetical }) }
                items(projects.filter { it.name.contains(query, true) }.let { if (alphabetical) it.sortedBy { p -> p.name.lowercase() } else it }, key = { it.id }) { item ->
                    Card(
                        onClick = { onOpen(item) },
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(item.name, modifier = Modifier.weight(1f).padding(20.dp), style = MaterialTheme.typography.titleMedium)
                            EntryActions(item.name, { onManage(item.id, it) }, { onManage(item.id, null) })
                        }
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
    onManage: (String, Long, String?) -> Unit,
    onCreateService: (String) -> Unit,
    onCreateSecret: (Long, SecretDraft, () -> Unit, (String) -> Unit) -> Unit
) {
    var query by remember { mutableStateOf("") }
    var alphabetical by remember { mutableStateOf(false) }
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
            item { SearchSort(query, { query = it }, alphabetical, { alphabetical = !alphabetical }) }
            items(services.filter { it.service.name.contains(query, true) || it.secrets.any { secret -> secret.name.contains(query, true) } }
                .let { if (alphabetical) it.sortedBy { b -> b.service.name.lowercase() } else it }, key = { it.service.id }) { bundle ->
                Card(Modifier.fillMaxWidth()) {
                    Row(
                        Modifier.fillMaxWidth().padding(start = 16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(bundle.service.name, modifier = Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
                        EntryActions(bundle.service.name,
                            { onManage("services", bundle.service.id, it) }, { onManage("services", bundle.service.id, null) })
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
                            maskEpoch = maskEpoch,
                            onRename = { onManage("secrets", secret.id, it) },
                            onDelete = { onManage("secrets", secret.id, null) },
                            onEdit = { draft, done, fail -> onCreateSecret(secret.serviceId, draft.copy(id = secret.id), done, fail) }
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
    maskEpoch: Int,
    onRename: (String) -> Unit,
    onDelete: () -> Unit,
    onEdit: (SecretDraft, () -> Unit, (String) -> Unit) -> Unit
) {
    val context = LocalContext.current
    val currentEpoch by rememberUpdatedState(maskEpoch)
    var recoveryMode by remember { mutableStateOf(false) }
    var editing by remember { mutableStateOf(false) }
    var value by remember(secret) { mutableStateOf<String?>(null) }
    var passwordDialog by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(value) {
        if (value != null) {
            delay(30_000)
            value = null
        }
    }
    LaunchedEffect(maskEpoch) { value = null; editing = false; passwordDialog = false }

    fun reveal() {
        if (!secret.readable) { error = "鍵の消失または改ざんを検出しました。設定からバックアップを復元してください。"; return }
        error = null
        val requestedEpoch = maskEpoch
        when (secret.authType) {
            AuthType.NONE -> runCatching {
                cryptoManager.decryptWithoutAuthentication(secret.encryptedValue, secret.iv)
            }.onSuccess { value = it }.onFailure { error = "復号できません。データ破損または鍵の消失が考えられます。設定からバックアップを復元してください。" }

            AuthType.PASSWORD -> { recoveryMode = false; passwordDialog = true }

            AuthType.BIOMETRIC -> runCatching {
                cryptoManager.newBiometricDecryptCipher(secret.iv, com.tanuki276.keybooks.security.Envelope.isEnvelope(secret.encryptedValue))
            }.onSuccess { cipher ->
                biometricGate.authenticate(
                    cipher = cipher,
                    title = secret.name,
                    onSuccess = { authenticated ->
                        runCatching { cryptoManager.decryptWithAuthenticatedCipher(authenticated, secret.encryptedValue) }
                            .onSuccess { if (currentEpoch == requestedEpoch) value = it }
                            .onFailure { error = "復号できません。データ破損または鍵の消失が考えられます。設定からバックアップを復元してください。" }
                    },
                    onError = { error = it }
                )
            }.onFailure { error = "生体認証鍵が無効です。指紋の再登録などで鍵が失われた可能性があります。設定からバックアップを復元してください。" }
        }
    }

    Column(Modifier.fillMaxWidth().padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(secret.name, modifier = Modifier.weight(1f), style = MaterialTheme.typography.labelLarge)
            EntryActions(secret.name, onRename, onDelete)
            TextButton(onClick = { if (value == null) reveal() else editing = true }) { Text(if (value == null) "解除して編集" else "値を編集") }
        }
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
        if (secret.authType == AuthType.BIOMETRIC && secret.recovery != null) {
            TextButton(onClick = { recoveryMode = true; passwordDialog = true }) { Text("回復パスワードで解除") }
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    }

    if (editing && value != null) SecretDialog(
        initial = secret, initialValue = value!!,
        onDismiss = { editing = false },
        onSave = { draft, fail -> onEdit(draft, { editing = false; value = null }, fail) })
    if (passwordDialog) {
        PasswordDialog(
            onDismiss = { passwordDialog = false },
            onSubmit = { password, wrong ->
                val recovery = if (recoveryMode) secret.recovery else null
                val salt = recovery?.passwordSalt ?: secret.passwordSalt ?: return@PasswordDialog
                runCatching {
                    cryptoManager.decryptWithPassword(recovery?.encryptedValue ?: secret.encryptedValue, recovery?.iv ?: secret.iv, salt, password)
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
    onBackup: () -> Unit,
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
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                TextButton(onClick = onBackup) { Text("暗号化Export / Import") }
                Text("端末故障・アンインストールに備え、バックアップを端末外へ保存してください。生体認証の再登録前にもExportしてください。")
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
    val password: String,
    val id: Long? = null
)

@Composable
private fun SecretDialog(
    initial: SecretItem? = null,
    initialValue: String = "",
    onDismiss: () -> Unit,
    onSave: (SecretDraft, (String) -> Unit) -> Unit
) {
    var name by remember { mutableStateOf(initial?.name ?: "") }
    var value by remember { mutableStateOf(initialValue) }
    var hidden by remember { mutableStateOf(initial?.hidden ?: true) }
    var auth by remember { mutableStateOf(initial?.authType ?: AuthType.NONE) }
    var password by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf("") }
    var saving by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = { if (!saving) onDismiss() },
        title = { Text(if (initial == null) "機密情報を追加" else "機密情報を編集") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
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
                if (auth == AuthType.PASSWORD || auth == AuthType.BIOMETRIC) {
                    OutlinedTextField(
                        password,
                        { password = it },
                        label = { Text(if (auth == AuthType.BIOMETRIC) "回復パスワード（12文字以上）" else "保護パスワード") },
                        visualTransformation = PasswordVisualTransformation()
                    )
                    OutlinedTextField(confirmation, { confirmation = it },
                        label = { Text("パスワードの確認") }, visualTransformation = PasswordVisualTransformation())
                }
                if (auth == AuthType.BIOMETRIC) Text("指紋の再登録で鍵が無効になった場合は、このパスワードで解除できます。端末外バックアップも作成してください。")
                if (auth != AuthType.NONE) PasswordStrength.warning(password)?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            Button(
                onClick = { saving = true; onSave(SecretDraft(name.trim(), value, hidden, auth, password)) { error = it; saving = false } },
                enabled = !saving && (auth == AuthType.NONE || password == confirmation) && name.isNotBlank() && value.isNotBlank() && (auth != AuthType.PASSWORD || password.isNotBlank()) && (auth != AuthType.BIOMETRIC || password.length >= 12)
            ) { Text("保存") }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !saving) { Text("キャンセル") } }
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
                if (wrong) Text("パスワードが違うか、データが破損しています。バックアップからの復元も確認してください。", color = MaterialTheme.colorScheme.error)
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

@Composable
private fun SearchSort(query: String, onQuery: (String) -> Unit, alphabetical: Boolean, onSort: () -> Unit) {
    Column(Modifier.fillMaxWidth().padding(16.dp)) {
        OutlinedTextField(query, onQuery, modifier = Modifier.fillMaxWidth(), label = { Text("名前で検索") }, singleLine = true)
        TextButton(onClick = onSort) { Text(if (alphabetical) "並び順: 名前順" else "並び順: 登録順") }
    }
}

@Composable
private fun EntryActions(name: String, onRename: (String) -> Unit, onDelete: () -> Unit) {
    var menu by remember { mutableStateOf(false) }
    var edit by remember { mutableStateOf(false) }
    var delete by remember { mutableStateOf(false) }
    var text by remember(name) { mutableStateOf(name) }
    Box {
        TextButton(onClick = { menu = true }) { Text("操作") }
        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
            DropdownMenuItem(text = { Text("名前変更") }, onClick = { menu = false; edit = true })
            DropdownMenuItem(text = { Text("削除") }, onClick = { menu = false; delete = true })
        }
    }
    if (edit) AlertDialog(onDismissRequest = { edit = false }, title = { Text("名前を変更") },
        text = { OutlinedTextField(text, { text = it }, singleLine = true) },
        confirmButton = { TextButton(onClick = { onRename(text.trim()); edit = false }, enabled = text.isNotBlank()) { Text("保存") } },
        dismissButton = { TextButton(onClick = { edit = false }) { Text("キャンセル") } })
    if (delete) AlertDialog(onDismissRequest = { delete = false }, title = { Text("削除の確認") },
        text = { Text("「$name」と配下の全データを削除します。この操作は取り消せません。") },
        confirmButton = { TextButton(onClick = { onDelete(); delete = false }) { Text("削除する") } },
        dismissButton = { TextButton(onClick = { delete = false }) { Text("キャンセル") } })
}
