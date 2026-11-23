# JeecgBoot Authentication & Authorization Security Review

**Scope:** AuthN/AuthZ only (missing auth, privilege escalation, IDOR, token/session flaws, unauthenticated sensitive endpoints).  
**Tree:** `/workspace` (JeecgBoot 3.9.5, JimuReport/JimuBI 2.5.4).  
**Method:** Full-chain source tracing from Shiro/JWT entry points; speculative issues omitted.

---

## Exploitability confirmation (requested candidates)

| Candidate | Exploitable in THIS version? | Notes |
|-----------|------------------------------|-------|
| `passwordChange` unauth reset | **No** (without SMS) | Requires Redis SMS code; forget-password path binds `username` in Redis; username+phone DB match required. |
| JWT default secret forgery | **No** | JWT HMAC uses **user password hash**, not a global JWT secret. |
| User enumeration | **Yes** | `/sys/user/checkOnlyUser` is Shiro `anon` and reveals existence. |
| Unauthenticated file download | **Yes** | `/sys/common/static/**` is `anon`; any uploaded whitelist-type file is fetchable if path known. |
| `/jmreport/**` full unauth engine | **No** (as blanket bypass) | Shiro `anon` is intentional; Jimu `JimuReportTokenInterceptor` + `JimuReportTokenService.verifyToken` gate APIs. `/jmreport/auto/export` now requires roles/perms in 2.5.4. Share whitelist still allows unauth data APIs when a share exists. |
| `/sys/user/register` priv-esc | **No** | Requires SMS; `addUserWithRole(user, "")` assigns **no** roles. Open registration still creates a normal account if SMS works. |

---

## Findings

### 1. Druid monitor anonymous + default credentials

- **Severity:** CRITICAL  
- **Primary location:** `jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/config/shiro/ShiroConfig.java`  
- **Evidence:**
  - `ShiroConfig.java:135` — `filterChainDefinitionMap.put("/druid/**", "anon");`
  - `application-prod.yml:104-109` (and other profiles) — `stat-view-servlet.enabled: true`, `loginUsername: admin`, `loginPassword: 123456`, empty `allow:`
- **Description:** Shiro skips JWT for all `/druid/**`. Druid’s own login uses the well-known default `admin/123456` with no IP allowlist, including in `application-prod.yml`.
- **Impact:** Unauthenticated network attackers who know the default password gain the Druid console (SQL/connection/session metrics; further DB impact depending on console features and deployment).
- **Attack path:**
  1. Request `GET /jeecg-boot/druid/index.html` (no `X-Access-Token`).
  2. Authenticate to Druid with `admin` / `123456`.
  3. Inspect datasource URLs, SQL, and runtime metrics; pivot as environment allows.
- **Remediation:** Remove `/druid/**` from Shiro `anon` (or bind behind admin auth); set `enabled: false` in production; set a strong unique password; restrict `allow` to admin IPs.

---

### 2. Unauthenticated upload download IDOR (`/sys/common/static/**`)

- **Severity:** HIGH  
- **Primary location:** `jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/controller/CommonController.java`  
- **Evidence:**
  - `ShiroConfig.java:121` — `/sys/common/static/**` → `anon`
  - `CommonController.java:188-224` — `view()` streams `uploadpath + imgPath` after weak `..` strip and extension whitelist
- **Description:** Any client can download files under the upload root without a JWT if they know/guess the relative path. Allowed types include `pdf`, `doc(x)`, `xls(x)`, `zip`, `csv`, etc. (`SsrfFileTypeFilter` whitelist). Filenames are `{original}_{timestamp}.ext`, often leaked by authenticated APIs or UI responses.
- **Impact:** Confidential business documents and PII in uploads are readable without authentication (classic unauthenticated IDOR).
- **Attack path:**
  1. Obtain a path (response leak, referrer, enumeration of known name + timestamp window, or prior authenticated browse).
  2. `GET /jeecg-boot/sys/common/static/{path}` with no token.
  3. Receive `Content-Disposition: attachment` file bytes.
- **Remediation:** Require authentication (and ideally object-level authorization) for non-public assets; use unguessable object IDs; separate public vs private storage; canonicalize paths and reject escapes with `getCanonicalFile()` under upload root.

---

### 3. Password reset does not invalidate existing JWT sessions

- **Severity:** HIGH  
- **Primary location:** `jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/config/shiro/ShiroRealm.java`  
- **Evidence:**
  - `SysUserController.java:1343-1401` — `passwordChange` updates password, clears only SMS Redis key, **does not** delete `PREFIX_USER_TOKEN*` keys
  - `ShiroRealm.java:200-225` — `jwtTokenRefresh`: if Redis still has `PREFIX_USER_TOKEN + token`, returns `true`; when verify fails (password changed), **re-signs** with the new password and keeps the old token key alive
- **Description:** After a successful SMS password reset, any previously issued JWT that still exists in Redis continues to authenticate. The refresh logic upgrades the cached signature to the new password instead of rejecting the session.
- **Impact:** Stolen sessions survive password reset; account takeover is not remediated by resetting the password.
- **Attack path:**
  1. Attacker obtains a valid victim JWT (XSS, device theft, log leak).
  2. Victim (or helpdesk flow) calls `/sys/user/passwordChange` and sets a new password.
  3. Attacker continues calling APIs with the **same** `X-Access-Token`.
  4. `jwtTokenRefresh` finds the Redis key, fails verify against the new password, writes a new signed value, returns success — attacker remains logged in.
- **Remediation:** On password change/reset, delete all `PREFIX_USER_TOKEN*` (and related) entries for that user; optionally maintain a password-version claim and reject mismatched tokens.

---

### 4. Authenticated user IDOR / over-broad user APIs (missing `@RequiresPermissions`)

- **Severity:** HIGH  
- **Primary location:** `jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/controller/SysUserController.java`  
- **Evidence:**
  - `SysUserController.java:627-635` — `/queryByIds` returns full `SysUser` entities for arbitrary IDs with **no** `@RequiresPermissions`
  - `SysUserController.java:1464-1488` — `/appUserList` pages all non-deleted users for any authenticated caller
  - `SysUserController.java:1501-1512` — `/recycleBin` lists logically deleted users without permission check  
  (Password/salt are `@JsonProperty(WRITE_ONLY)`, but phone/email/realname/org and other PII remain.)
- **Description:** JWT is required (not Shiro `anon`), but any low-privilege logged-in user can read arbitrary users by ID, search the full user directory, and view the recycle bin.
- **Impact:** Horizontal privilege escalation / mass PII disclosure inside the tenant.
- **Attack path:**
  1. Register or use any low-priv account that can log in.
  2. `GET /sys/user/queryByIds?userIds=<adminId>,...` or `GET /sys/user/appUserList?pageNo=1&pageSize=100`.
  3. Collect usernames, phones, emails; use for further attacks (SMS reset targeting, phishing).
- **Remediation:** Add `@RequiresPermissions` consistent with `/listAll` / admin user APIs; apply data-scope filters; return DTOs with minimal fields.

---

### 5. Unauthenticated username enumeration via `checkOnlyUser`

- **Severity:** MEDIUM  
- **Primary location:** `jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/controller/SysUserController.java`  
- **Evidence:**
  - `ShiroConfig.java:117` — `/sys/user/checkOnlyUser` → `anon`
  - `SysUserController.java:390-411` — returns success=false / “用户账号已存在” when a user matches
- **Description:** Anonymous callers can probe whether a username (or other bound `SysUser` fields in the query object) already exists.
- **Impact:** Facilitates targeted password spraying and account mapping (especially with default `admin` and captcha disabled in dev).
- **Attack path:**
  1. `GET /sys/user/checkOnlyUser?username=admin` (no token).
  2. Distinct responses for exists vs not.
  3. Repeat for candidate usernames.
- **Remediation:** Remove from Shiro `anon`, or always return a uniform response; rate-limit; require captcha/signature.

---

### 6. Hardcoded request-signature secret (SMS and signed anon APIs)

- **Severity:** MEDIUM  
- **Primary location:** `jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/config/JeecgBaseConfig.java`  
- **Evidence:**
  - `JeecgBaseConfig.java:25` — default `signatureSecret = "dd05f1c54d63749eda95f9fa6d49v442a"`
  - Same value in `application-*.yml` (`signatureSecret`)
  - `signUrls` includes `/sys/sms` (e.g. `application-dev.yml:280`)
  - `SignAuthInterceptor` / `SignUtil.verifySign` gate those URLs
- **Description:** The shared default signing key is public in the repository. Anyone can compute valid `X-SIGN` / `X-TIMESTAMP` headers for `/sys/sms` and other signed-but-Shiro-anon endpoints.
- **Impact:** Bypasses the signature anti-abuse control; enables SMS send attempts (cost/DoS) and signed dict/API abuse. Does **not** alone complete `passwordChange` (SMS code still required).
- **Attack path:**
  1. Read default `signatureSecret` from shipped config.
  2. Build request body + timestamp; MD5-sign per `SignUtil`.
  3. `POST /sys/sms` with forged headers as an anonymous client.
- **Remediation:** Require unique secrets per deployment (fail startup if default); rotate; treat signing as insufficient without auth for sensitive actions.

---

### 7. Hardcoded AES key/IV for password transport (`getEncryptedString`)

- **Severity:** MEDIUM  
- **Primary location:** `jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/common/util/encryption/EncryptedString.java`  
- **Evidence:**
  - `EncryptedString.java:16-21` — fixed `key` / `iv`
  - `ShiroConfig.java:113` — `/sys/getEncryptedString` → `anon`
  - `LoginController.java:624-631` — returns that key/iv to any client
- **Description:** Login password “encryption” uses a publicly known AES key. The endpoint even serves the key material anonymously.
- **Impact:** Network observers (or malicious frontends) can decrypt login password ciphertext; encryption provides no confidentiality against anyone who read the source or called this API.
- **Attack path:**
  1. `GET /sys/getEncryptedString` (or use constants from source).
  2. Intercept login POST body.
  3. AES-decrypt password with returned key/iv; reuse credentials.
- **Remediation:** Use TLS as the confidentiality layer; if client-side crypto remains, use per-session server-generated keys (RSA/ECDH), never ship static keys.

---

### 8. JimuReport share-gated unauthenticated data APIs (design residual)

- **Severity:** MEDIUM  
- **Primary location:** `jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/config/jimureport/JimuReportTokenService.java` (integration) + JimuReport 2.5.4 `ShareUrlEnum`  
- **Evidence:**
  - `ShiroConfig.java:147` — `/jmreport/**` → `anon`
  - `JimuReportTokenService.java:68-69` — `verifyToken` delegates to `TokenUtils.verifyToken`
  - JimuReport 2.5.4 `ShareUrlEnum` includes `/jmreport/qurestSql`, `/jmreport/getQueryInfo`, `/jmreport/show`, export streams, etc.
  - `/jmreport/auto/export` in 2.5.4 requires `admin|lowdeveloper` + `jmreport:exportJob:export` (prior CVE-class unauth export **fixed**)
- **Description:** Blanket Shiro anon is intentional. Without a share, API calls fail token verification. With an **active password-less share**, Jimu’s interceptor allows share-whitelisted endpoints without a user JWT, exposing report SQL/API datasets to anyone who can reach the share/report IDs.
- **Impact:** Unauthenticated read of report-backed business data on deployments that publish password-less shares (common for dashboards).
- **Attack path:**
  1. Discover or receive a password-less share / report id.
  2. Call share-allowed endpoints (e.g. `getQueryInfo` → `qurestSql`) with no JWT.
  3. Read dataset results from the report datasource.
- **Remediation:** Require share tokens/passwords by default; shrink `ShareUrlEnum`; avoid mapping application DB as report datasource for public shares; keep `lowCodeMode: prod` (already set in `application-prod.yml`).

---

## Non-findings / hardened paths (for the requested checklist)

- **`passwordChange`:** SMS Redis proof + username bind (forget mode) + username/phone consistency — not a free unauth reset in this tree. Residual: GET transmits password in query string (logging risk); no session kill (Finding 3).
- **JWT “default secret”:** N/A — signing key is the user’s password hash (`JwtUtil.sign/verify`). Forgery requires the password (or Redis session theft).
- **`register`:** SMS required; empty role string → no admin role assignment. Risk is open account creation only when SMS provider is configured and reachable.
- **Jimu `/jmreport/auto/export` pre-auth export/RCE class:** Not present as unauthenticated in bundled **2.5.4** (export route is role/permission protected; NoLogin limited to signed python plugin / signed download paths).

---

## Priority remediation order

1. Lock down Druid (Finding 1).  
2. Invalidate tokens on password change (Finding 3).  
3. Authenticate/authorize static downloads (Finding 2).  
4. Permission-gate user query APIs (Finding 4).  
5. Rotate signature/AES secrets and close enumeration (Findings 5–7).  
6. Harden Jimu share policy (Finding 8).
