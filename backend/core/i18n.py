"""
Backend internationalization support.

Provides translated error messages based on the Accept-Language header.
"""
from fastapi import Request
from typing import Optional

SUPPORTED_LOCALES = {"en", "ja", "fr", "de", "he", "ru", "zh", "es", "pt", "nl", "ar", "it"}
DEFAULT_LOCALE = "en"

# Error message translations keyed by message ID
TRANSLATIONS = {
    "email_exists": {
        "en": "Email already registered",
        "ja": "このメールアドレスは既に登録されています",
        "fr": "Cet e-mail est déjà enregistré",
        "de": "Diese E-Mail ist bereits registriert",
        "he": "דוא\"ל כבר רשום",
        "ru": "Эта почта уже зарегистрирована",
        "zh": "该邮箱已被注册",
        "es": "Este correo ya está registrado",
        "pt": "Este e-mail já está registrado",
        "nl": "Dit e-mailadres is al geregistreerd",
        "ar": "هذا البريد الإلكتروني مسجل بالفعل",
        "it": "Questa email è già registrata",
    },
    "password_too_short": {
        "en": "Password must be at least 8 characters",
        "ja": "パスワードは8文字以上必要です",
        "fr": "Le mot de passe doit comporter au moins 8 caractères",
        "de": "Passwort muss mindestens 8 Zeichen lang sein",
        "he": "הסיסמה חייבת להכיל לפחות 8 תווים",
        "ru": "Пароль должен содержать не менее 8 символов",
        "zh": "密码至少需要8个字符",
        "es": "La contraseña debe tener al menos 8 caracteres",
        "pt": "A senha deve ter pelo menos 8 caracteres",
        "nl": "Wachtwoord moet minstens 8 tekens bevatten",
        "ar": "يجب أن تتكون كلمة المرور من 8 أحرف على الأقل",
        "it": "La password deve contenere almeno 8 caratteri",
    },
    "invalid_credentials": {
        "en": "Invalid email or password",
        "ja": "メールアドレスまたはパスワードが無効です",
        "fr": "E-mail ou mot de passe invalide",
        "de": "Ungültige E-Mail oder ungültiges Passwort",
        "he": "דוא\"ל או סיסמה לא חוקיים",
        "ru": "Неверная почта или пароль",
        "zh": "邮箱或密码无效",
        "es": "Correo o contraseña no válidos",
        "pt": "E-mail ou senha inválidos",
        "nl": "Ongeldig e-mailadres of wachtwoord",
        "ar": "بريد إلكتروني أو كلمة مرور غير صالحة",
        "it": "Email o password non validi",
    },
    "account_deactivated": {
        "en": "Account is deactivated",
        "ja": "アカウントが無効化されています",
        "fr": "Le compte est désactivé",
        "de": "Konto ist deaktiviert",
        "he": "החשבון מושבת",
        "ru": "Аккаунт деактивирован",
        "zh": "账户已停用",
        "es": "La cuenta está desactivada",
        "pt": "A conta está desativada",
        "nl": "Account is gedeactiveerd",
        "ar": "الحساب معطل",
        "it": "L'account è disattivato",
    },
    "org_deactivated": {
        "en": "Organization is deactivated",
        "ja": "組織が無効化されています",
        "fr": "L'organisation est désactivée",
        "de": "Organisation ist deaktiviert",
        "he": "הארגון מושבת",
        "ru": "Организация деактивирована",
        "zh": "组织已停用",
        "es": "La organización está desactivada",
        "pt": "A organização está desativada",
        "nl": "Organisatie is gedeactiveerd",
        "ar": "المؤسسة معطلة",
        "it": "L'organizzazione è disattivata",
    },
    "auth_required": {
        "en": "Authentication required",
        "ja": "認証が必要です",
        "fr": "Authentification requise",
        "de": "Authentifizierung erforderlich",
        "he": "נדרש אימות",
        "ru": "Требуется аутентификация",
        "zh": "需要身份验证",
        "es": "Se requiere autenticación",
        "pt": "Autenticação necessária",
        "nl": "Authenticatie vereist",
        "ar": "المصادقة مطلوبة",
        "it": "Autenticazione richiesta",
    },
    "invalid_token": {
        "en": "Invalid or expired token",
        "ja": "トークンが無効または期限切れです",
        "fr": "Jeton invalide ou expiré",
        "de": "Token ungültig oder abgelaufen",
        "he": "אסימון לא חוקי או שפג תוקפו",
        "ru": "Недействительный или просроченный токен",
        "zh": "令牌无效或已过期",
        "es": "Token no válido o expirado",
        "pt": "Token inválido ou expirado",
        "nl": "Ongeldig of verlopen token",
        "ar": "رمز غير صالح أو منتهي الصلاحية",
        "it": "Token non valido o scaduto",
    },
    "user_not_found": {
        "en": "User not found or inactive",
        "ja": "ユーザーが見つからないか無効です",
        "fr": "Utilisateur introuvable ou inactif",
        "de": "Benutzer nicht gefunden oder inaktiv",
        "he": "המשתמש לא נמצא או אינו פעיל",
        "ru": "Пользователь не найден или неактивен",
        "zh": "用户未找到或已停用",
        "es": "Usuario no encontrado o inactivo",
        "pt": "Usuário não encontrado ou inativo",
        "nl": "Gebruiker niet gevonden of inactief",
        "ar": "المستخدم غير موجود أو غير نشط",
        "it": "Utente non trovato o inattivo",
    },
    "wrong_password": {
        "en": "Current password is incorrect",
        "ja": "現在のパスワードが正しくありません",
        "fr": "Le mot de passe actuel est incorrect",
        "de": "Aktuelles Passwort ist falsch",
        "he": "הסיסמה הנוכחית שגויה",
        "ru": "Текущий пароль неверен",
        "zh": "当前密码不正确",
        "es": "La contraseña actual es incorrecta",
        "pt": "A senha atual está incorreta",
        "nl": "Huidig wachtwoord is onjuist",
        "ar": "كلمة المرور الحالية غير صحيحة",
        "it": "La password attuale non è corretta",
    },
    "cannot_change_own_role": {
        "en": "Cannot change your own role",
        "ja": "自分のロールは変更できません",
        "fr": "Vous ne pouvez pas modifier votre propre rôle",
        "de": "Eigene Rolle kann nicht geändert werden",
        "he": "לא ניתן לשנות את התפקיד שלך",
        "ru": "Нельзя изменить собственную роль",
        "zh": "无法更改自己的角色",
        "es": "No puedes cambiar tu propio rol",
        "pt": "Não é possível alterar sua própria função",
        "nl": "Je kunt je eigen rol niet wijzigen",
        "ar": "لا يمكنك تغيير دورك الخاص",
        "it": "Non puoi modificare il tuo ruolo",
    },
    "cannot_deactivate_self": {
        "en": "Cannot deactivate yourself",
        "ja": "自分自身を無効化できません",
        "fr": "Vous ne pouvez pas vous désactiver",
        "de": "Selbstdeaktivierung nicht möglich",
        "he": "לא ניתן להשבית את עצמך",
        "ru": "Нельзя деактивировать себя",
        "zh": "无法停用自己的账户",
        "es": "No puedes desactivarte a ti mismo",
        "pt": "Não é possível desativar a si mesmo",
        "nl": "Je kunt jezelf niet deactiveren",
        "ar": "لا يمكنك تعطيل حسابك",
        "it": "Non puoi disattivare te stesso",
    },
    "cannot_delete_self": {
        "en": "Cannot delete yourself",
        "ja": "自分自身を削除できません",
        "fr": "Vous ne pouvez pas vous supprimer",
        "de": "Selbstlöschung nicht möglich",
        "he": "לא ניתן למחוק את עצמך",
        "ru": "Нельзя удалить себя",
        "zh": "无法删除自己的账户",
        "es": "No puedes eliminarte a ti mismo",
        "pt": "Não é possível excluir a si mesmo",
        "nl": "Je kunt jezelf niet verwijderen",
        "ar": "لا يمكنك حذف حسابك",
        "it": "Non puoi eliminare te stesso",
    },
    "cannot_delete_superadmin": {
        "en": "Cannot delete a superadmin",
        "ja": "スーパー管理者は削除できません",
        "fr": "Impossible de supprimer un super administrateur",
        "de": "Superadmin kann nicht gelöscht werden",
        "he": "לא ניתן למחוק מנהל-על",
        "ru": "Нельзя удалить суперадмина",
        "zh": "无法删除超级管理员",
        "es": "No se puede eliminar a un superadmin",
        "pt": "Não é possível excluir um superadmin",
        "nl": "Kan een superadmin niet verwijderen",
        "ar": "لا يمكن حذف مدير أعلى",
        "it": "Impossibile eliminare un superadmin",
    },
    "superadmin_only": {
        "en": "Only superadmin can grant superadmin role",
        "ja": "スーパー管理者のみがスーパー管理者ロールを付与できます",
        "fr": "Seul un super admin peut accorder le rôle super admin",
        "de": "Nur ein Superadmin kann die Superadmin-Rolle vergeben",
        "he": "רק מנהל-על יכול להעניק תפקיד מנהל-על",
        "ru": "Только суперадмин может назначить роль суперадмина",
        "zh": "只有超级管理员才能授予超级管理员角色",
        "es": "Solo un superadmin puede otorgar el rol de superadmin",
        "pt": "Apenas um superadmin pode conceder a função de superadmin",
        "nl": "Alleen een superadmin kan de superadmin-rol toekennen",
        "ar": "فقط المدير الأعلى يمكنه منح دور المدير الأعلى",
        "it": "Solo un superadmin può assegnare il ruolo di superadmin",
    },
    "mssp_only": {
        "en": "Only MSSP organizations can create client orgs",
        "ja": "MSSP組織のみがクライアント組織を作成できます",
        "fr": "Seules les organisations MSSP peuvent créer des organisations clientes",
        "de": "Nur MSSP-Organisationen können Client-Organisationen erstellen",
        "he": "רק ארגוני MSSP יכולים ליצור ארגוני לקוח",
        "ru": "Только организации MSSP могут создавать клиентские организации",
        "zh": "只有 MSSP 组织才能创建客户组织",
        "es": "Solo las organizaciones MSSP pueden crear organizaciones cliente",
        "pt": "Apenas organizações MSSP podem criar organizações cliente",
        "nl": "Alleen MSSP-organisaties kunnen klantorganisaties aanmaken",
        "ar": "فقط مؤسسات MSSP يمكنها إنشاء مؤسسات عميلة",
        "it": "Solo le organizzazioni MSSP possono creare organizzazioni cliente",
    },
    "role_exists": {
        "en": "A role with this name already exists in your organization",
        "ja": "この名前のロールは既にこの組織に存在します",
        "fr": "Un rôle portant ce nom existe déjà dans votre organisation",
        "de": "Eine Rolle mit diesem Namen existiert bereits in Ihrer Organisation",
        "he": "תפקיד בשם זה כבר קיים בארגון שלך",
        "ru": "Роль с таким именем уже существует в вашей организации",
        "zh": "该名称的角色在您的组织中已存在",
        "es": "Ya existe un rol con este nombre en tu organización",
        "pt": "Uma função com este nome já existe em sua organização",
        "nl": "Een rol met deze naam bestaat al in je organisatie",
        "ar": "يوجد دور بهذا الاسم بالفعل في مؤسستك",
        "it": "Un ruolo con questo nome esiste già nella tua organizzazione",
    },
    "no_access": {
        "en": "No access to requested organization",
        "ja": "要求された組織へのアクセス権がありません",
        "fr": "Pas d'accès à l'organisation demandée",
        "de": "Kein Zugriff auf die angeforderte Organisation",
        "he": "אין גישה לארגון המבוקש",
        "ru": "Нет доступа к запрашиваемой организации",
        "zh": "无权访问请求的组织",
        "es": "Sin acceso a la organización solicitada",
        "pt": "Sem acesso à organização solicitada",
        "nl": "Geen toegang tot de gevraagde organisatie",
        "ar": "لا يوجد وصول إلى المؤسسة المطلوبة",
        "it": "Nessun accesso all'organizzazione richiesta",
    },
    "forbidden": {
        "en": "Access denied",
        "ja": "アクセスが拒否されました",
        "fr": "Accès refusé",
        "de": "Zugriff verweigert",
        "he": "הגישה נדחתה",
        "ru": "Доступ запрещён",
        "zh": "访问被拒绝",
        "es": "Acceso denegado",
        "pt": "Acesso negado",
        "nl": "Toegang geweigerd",
        "ar": "تم رفض الوصول",
        "it": "Accesso negato",
    },
}


def parse_accept_language(accept_language: Optional[str]) -> str:
    """Parse Accept-Language header and return the best matching locale."""
    if not accept_language:
        return DEFAULT_LOCALE

    # Parse quality values: e.g. "ja,en-US;q=0.9,en;q=0.8"
    languages = []
    for part in accept_language.split(","):
        part = part.strip()
        if ";q=" in part:
            lang, q = part.split(";q=")
            try:
                languages.append((lang.strip(), float(q)))
            except ValueError:
                languages.append((lang.strip(), 1.0))
        else:
            languages.append((part, 1.0))

    # Sort by quality (descending)
    languages.sort(key=lambda x: x[1], reverse=True)

    for lang, _ in languages:
        # Try exact match first
        code = lang.lower().split("-")[0]
        if code in SUPPORTED_LOCALES:
            return code

    return DEFAULT_LOCALE


def get_locale_from_request(request: Request) -> str:
    """Extract locale from request (Accept-Language header)."""
    accept_lang = request.headers.get("Accept-Language", "")
    return parse_accept_language(accept_lang)


def t(message_id: str, locale: str = DEFAULT_LOCALE, **kwargs) -> str:
    """Get translated message by ID and locale.

    Falls back to English if locale or message_id not found.
    Supports keyword interpolation: t("hello", name="World") with "{name}" in the message.
    """
    messages = TRANSLATIONS.get(message_id, {})
    msg = messages.get(locale, messages.get(DEFAULT_LOCALE, message_id))
    if kwargs:
        try:
            msg = msg.format(**kwargs)
        except (KeyError, IndexError):
            pass
    return msg
