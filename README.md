# CyberShieldHub — Модуль 18

Навчальний ASP.NET Core API (.NET 10): CORS, обмеження запитів за IP, очищення HTML-коментарів та захисні HTTP-заголовки. Класного проєкту й методички `Module18/README.md` у робочій папці не було, тому створено окремий невеликий проєкт за вимогами домашнього завдання.

Для перевірки є демонстраційний JWT-вхід, один умовний рахунок і симуляція переказів. База даних не потрібна; справжні платежі не виконуються, баланс не змінюється.

## Запуск

Потрібен .NET 10 SDK.

```powershell
cd "G:\ч2\CyberShieldHub"
dotnet restore
dotnet run --project CyberShieldHub
```

За замовчуванням використовується HTTP-профіль із завдання: [Scalar](http://localhost:5298/scalar/v1). OpenAPI: http://localhost:5298/openapi/v1.json. Зупинка — `Ctrl+C`.

HTTPS-профіль:

```powershell
dotnet run --project CyberShieldHub --launch-profile https
```

Scalar: https://localhost:7181/scalar/v1. За потреби довірте локальний сертифікат командою `dotnet dev-certs https --trust`.

## Ендпоінти

| Метод і шлях | Призначення | Авторизація / ліміт |
| --- | --- | --- |
| `POST /api/auth/login` | Отримати демонстраційний JWT | 5 спроб за 60 секунд на IP |
| `GET /api/banking/accounts` | Умовний рахунок користувача | Bearer JWT |
| `POST /api/banking/transfers` | Імітація переказу | Bearer JWT; бакет 10 токенів, +2 кожні 10 секунд на IP |
| `POST /api/feedback` | Очистити коментар | Без токена |

Демонстраційний обліковий запис:

```json
{ "username": "demo", "password": "Demo!2026" }
```

Відповідь входу містить `accessToken`, `tokenType: "Bearer"`, `expiresInSeconds: 900`. У Scalar скопіюйте токен у поле Bearer у налаштуваннях Authentication. Логін і feedback не потребують токена. JWT перевіряється за підписом, issuer, audience, строком дії та алгоритмом HS256. Випадковий ключ існує тільки в пам'яті; після перезапуску треба ввійти знову.

Приклад переказу:

```json
{ "fromAccountId": 1, "toAccountId": 2, "amount": 10 }
```

Дозволено лише власний демонстраційний рахунок `1`, отримувач `2`, сума від 0.01 до 10000 UAH. Відповідь має статус `Simulated`. Без JWT повертається 401; спроба списання з іншого рахунку — 403.

## Rate Limiting

`Extensions/RateLimitingExtensions.cs` реєструє дві окремі політики через `AddCyberShieldRateLimiting()`:

- **login**: Fixed Window, 5 запитів на 60 секунд.
- **transfers**: Token Bucket, ємність 10, поповнення по 2 кожні 10 секунд.

Обидві політики використовують `Connection.RemoteIpAddress`; IPv4 та його IPv4-mapped IPv6 форма нормалізуються до одного ключа. Черга відключена. Ліміти входу й переказів незалежні. Навіть успішний вхід або запит із помилкою валідації витрачає дозвіл. У контролерах стоять `[EnableRateLimiting("...")]`, а в Program — `UseRateLimiter()`.

Після перевищення повертається **429**, JSON із `error`, `message`, `retryAfterSeconds`, `policy` та заголовки `Retry-After`, `X-RateLimit-Policy`. `Retry-After` обчислюється з метаданих лімітера з округленням угору: одразу після вичерпання вікна входу це приблизно 60 секунд, пізніше — залишок часу.

IP береться зі з'єднання, а не з довільного `X-Forwarded-For`. Надсилання підробленого forwarding-заголовка не створює новий бакет. Проксі-конфігурація не додається: у цьому проєкті клієнт звертається безпосередньо до Kestrel.

## XSS Sanitizer

`IXssSanitizerService` зареєстровано singleton. Реалізація використовує **HtmlSanitizer**, без регулярних виразів і простого порівняння рядків. Кожне очищення має окремий парсер та локальні обробники подій, тому одночасні запити не ділять прапорець виявлення.

Дозволене базове форматування: `b`, `strong`, `i`, `em`, `u`, `p`, `br`, `ul`, `ol`, `li`, `a`, `blockquote`, `code`. Атрибути — лише `href` і `title`, URL-схеми — HTTP, HTTPS, mailto. Скрипти, iframe, object, SVG, обробники подій, стилі та небезпечні URL видаляються. `ContainsDangerousContent` визначає видалення за подіями парсера; звичайна нормалізація `<br/>` до `<br>` не створює хибного спрацювання. Прапорець також спрацьовує на іншу заборонену розмітку, а не доводить намір користувача атакувати.

Запит:

```json
{ "comment": "Дякую! <script>alert('XSS')</script><b>Все супер</b>" }
```

Відповідь:

```json
{
  "sanitizedComment": "Дякую! <b>Все супер</b>",
  "isXssDetected": true
}
```

Коментар обов'язковий, до 4000 символів. Граничний розмір тіла запиту Kestrel — 64 КіБ.

## Security Headers

`UseCyberShieldSecurityHeaders()` стоїть першим middleware. Заголовки додаються через `OnStarting`, тому залишаються і на помилках, і на 429:

| Заголовок | Значення |
| --- | --- |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Content-Security-Policy` | `default-src 'self'; frame-ancestors 'none'; object-src 'none';` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `X-XSS-Protection` | `0` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-site` |
| `Cache-Control` | `no-store` |

Для сегментів `/scalar` та `/openapi` виключено лише строгий CSP, щоб документація могла виконати свою inline-ініціалізацію. Решта заголовків зберігаються. `/scalar-fake` не є виключенням. Заголовок `Server` у Kestrel вимкнено.

## CORS

Дозволений frontend origin — `http://localhost:3000`. Дозволені GET, POST, OPTIONS та вхідні Content-Type, Authorization. Заголовки Retry-After і X-RateLimit-Policy відкриті браузеру через `Access-Control-Expose-Headers`. Credentials для cookie не дозволені; використовується Bearer.

```powershell
curl.exe -i -H "Origin: http://localhost:3000" http://localhost:5298/api/banking/accounts
```

Без токена це 401, але CORS і захисні заголовки присутні. Для 200 додайте `-H "Authorization: Bearer ВАШ_ТОКЕН"`. Для стороннього Origin заголовок `Access-Control-Allow-Origin` не додається. OPTIONS обробляється до лімітера і не витрачає спроби входу. CORS також зберігається на відповідях 429.

## Перевірка через Scalar

1. Виконайте вхід `demo` / `Demo!2026`, додайте JWT у Bearer Authentication, відкрийте рахунки. Перевірте 9 захисних заголовків.
2. Надішліть XSS-коментар із прикладу вище — отримаєте очищений HTML і `isXssDetected: true`.
3. Загалом виконайте 6 швидких POST входу з одного IP. Успішний вхід із першого кроку також враховується. Шостий запит — 429 з Retry-After. Зачекайте до завершення вікна або перезапустіть навчальний сервер для нового тесту.
4. З отриманим JWT виконайте 10 швидких переказів — вони проходять. Одинадцятий — 429. Через 10 секунд доступні ще 2 спроби.
5. Документація має відкриватися без CSP-помилок у DevTools.

Приклади всіх запитів є у `CyberShieldHub/CyberShieldHub.http`.

## Тести

```powershell
dotnet test
```

**31 тест пройшов.** Перевіряються ліміти, IP-ізоляція, незалежність політик, реальне поповнення Token Bucket, підроблений X-Forwarded-For, CORS і preflight, JWT, помилки валідації, XSS-вектори, безпечне форматування, паралельне використання singleton, 9 заголовків на успіхах і помилках, CSP-виключення та OpenAPI.

Тести мають власний middleware для встановлення IP та контролер, що кидає виняток; ці компоненти існують тільки у тестовій збірці. Звичайний API не читає тестовий заголовок і не має тестового ендпоінту. Окремо всі основні сценарії перевірено на реальному Kestrel і Scalar у браузері.

Проєкт демонструє конкретні механізми цього модуля. Повний банківський backend, постійне зберігання користувачів і розподілені ліміти між кількома серверами до нього не входять.
