using System.Text.RegularExpressions;
using ModScanner.Core;
using ModScanner.Report;
using static ModScanner.Analysis.Vocab;

namespace ModScanner.Analysis;

/// <summary>
/// Внешняя авторизация: мод связывается со своим сервером, чтобы проверить лицензию/подписку/HWID
/// или получить токен, и (часто) подгружает оттуда код. Признаки: сеть + идентификация железа
/// (HWID/MAC/переменные окружения) + строки и классы лицензии + криптография, неизвестные адреса
/// в строках. Отдельно — самые опасные связки: загрузка классов из сети, скачивание и запуск файла,
/// отправка токена сессии Minecraft.
/// Авторизация в сервисах Microsoft/Mojang (смена аккаунта), Spotify, Discord — не считается.
/// </summary>
internal sealed class AuthAnalyzer : IAnalyzer
{
    public string Name => "Авторизация";

    private static readonly Regex AuthClassRx = new(
        @"(licen[cs]e|hwid|auth(?!or)|login|protect(ed|ion|or)|guard|devicecode|keyauth|whitelist|antileak|antidump)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // явная лицензия/защита — для следов вырезанной авторизации (без сети)
    private static readonly Regex LicenseClassRx = new(
        @"(licen[cs]e|hwid|keyauth|antileak|antidump|devicecode|deviceauth)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ReflClassRx = new(@"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*\.[A-Z][A-Za-z0-9_$]+$", RegexOptions.Compiled);

    private static readonly Regex UrlRx = new(@"(?:https?|wss?)://(?<host>[a-z0-9.\-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?[^\s""']*", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex HostOnlyRx = new(@"^(?<host>(?:[a-z0-9\-]+\.)+(?:com|net|org|ru|su|xyz|fun|gg|cc|io|dev|me|pro|club|site|online|store|tech|top|space|lol|wtf|best|host|app|shop|uk|de|fr|pl|ua|by|kz)|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:/.*)?$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // адреса, обращение к которым не говорит о собственной авторизации мода
    private static readonly string[] KnownHosts =
    {
        "modrinth.com", "github.com", "githubusercontent.com", "github.io", "curseforge.com", "forgecdn.net", "fabricmc.net", "quiltmc.org",
        "neoforged.net", "minecraftforge.net", "mojang.com", "minecraft.net", "minecraftservices.com", "microsoftonline.com", "live.com",
        "xboxlive.com", "microsoft.com", "msauth.net", "crafatar.com", "mc-heads.net", "minotar.net", "namemc.com", "optifine.net",
        "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "twitter.com", "x.com", "youtube.com", "twitch.tv", "w3.org",
        "apache.org", "json-schema.org", "localhost", "127.0.0.1", "0.0.0.0", "example.com", "example.org", "spotify.com", "google.com",
        "googleapis.com", "gstatic.com", "gnu.org", "opensource.org", "creativecommons.org", "viaversion.com", "oracle.com", "java.com",
        "openjdk.org", "sun.com", "jetbrains.com", "kotlinlang.org", "maven.org", "apple.com", "mozilla.org", "wikipedia.org",
        "plasmoverse.com", "plo.su", "lwjgl.org", "cloudflare.com", "jsdelivr.net", "patreon.com", "ko-fi.com", "paypal.com",
        "shedaniel.me", "terraformersmc.com", "wiki.vg", "minecraft.wiki", "fandom.com", "imgur.com", "gitlab.com", "bitbucket.org",
        "sentry.io", "mclo.gs", "paste.gg", "lunarclient.com", "badlion.net", "labymod.net", "essential.gg", "api.mojang.com",
        "xmlpull.org", "slf4j.org", "logging.apache.org", "netty.io", "json.org", "yaml.org", "xml.org", "schema.org", "iana.org",
        "ietf.org", "unicode.org", "khronos.org", "opengl.org", "wikimedia.org", "gravatar.com", "adoptium.net", "azul.com",
    };

    public void Run(ScanContext ctx)
    {
        var m = ctx.Model;
        CodeLoaders(ctx, m);

        // адреса по всему jar (строки часто лежат в отдельном классе-константах)
        var allHosts = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in m.OwnClasses)
            foreach (var mn in c.Methods)
                foreach (var s in mn.Strings)
                    foreach (var (host, url) in Hosts(s))
                    {
                        if (!allHosts.TryGetValue(host, out var l)) allHosts[host] = l = new List<string>();
                        if (l.Count < 4) l.Add($"{url}  [{c.SimpleName}]");
                    }
        var unknownHosts = allHosts.Where(kv => !IsKnown(kv.Key)).ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase);

        if (m.IsLibraryJar) return;

        // по логическим единицам (внешний класс + вложенные)
        var units = new List<(string Unit, AtomSet U, AtomSet D, List<ClassNode> Classes)>();
        foreach (var (outer, classes) in m.Units)
        {
            if (classes.All(c => c.IsLibrary)) continue;
            AtomSet u = default, dd = default;
            foreach (var c in classes) foreach (var mn in c.Methods) { u.Or(mn.Closure); dd.Or(mn.Direct); }
            units.Add((outer, u, dd, classes));
        }
        // вход в аккаунт Microsoft/Mojang (смена аккаунта, альт-менеджеры) — не собственная авторизация мода
        bool msAuth = m.OwnClasses.Any(c => c.Methods.Any(x => x.Strings.Any(s => s.Contains("microsoftonline.com") || s.Contains("login.live.com") || s.Contains("xboxlive.com") || s.Contains("minecraftservices.com"))));

        // токен текущей сессии уходит в сеть: в одном методе читается сессия игрока, её токен и есть сетевой запрос
        var tokenM = m.OwnClasses.SelectMany(c => c.Methods).FirstOrDefault(x => x.Closure.Has(GetUser) && x.Closure.Has(SessionToken) && Net(x.Closure));
        if (tokenM is not null)
        {
            var hostsT = UnitHosts(m.Units[tokenM.Owner.Outer]);
            if (hostsT.Count == 0 || hostsT.Any(h => !IsKnown(h)))
            {
                ctx.Add(new Finding
                {
                    Severity = Severity.Critical, Category = "Авторизация", Analyzer = Name, Weight = 30, Signal = "Кража токена сессии",
                    Location = tokenM.Owner.Name,
                    Title = $"Токен сессии Minecraft уходит в сеть ({tokenM.Owner.SimpleName})",
                    Why = "Метод берёт текущую сессию игрока, читает её токен доступа (User.getAccessToken / getSessionId) и выполняет сетевой запрос не к серверам Mojang/Microsoft. С этим токеном можно войти в аккаунт игрока. Иногда так же устроена «авторизация» чит-клиента по аккаунту Minecraft.",
                }.Ev("Где", Ev.Where(m, tokenM)).EvLines("Сессия и сеть", Ev.Atoms(m, tokenM, GetUser, SessionToken, Http, Socket, ReadNet, StrUrl)));
            }
        }

        bool anyNet = units.Any(x => Net(x.U));
        var authFindings = 0;
        var stubs = new List<string>();
        var reported = new HashSet<string>(StringComparer.Ordinal);

        foreach (var (outer, u, dd, classes) in units)
        {
            bool net = Net(u);
            bool hwid = HwidReal(classes) || dd.Has(StrHwid);
            bool nameAuth = AuthClassRx.IsMatch(Simple(outer));
            bool strongAuth = dd.Has(StrAuthStrong) || nameAuth;
            bool crypto = dd.Has(Crypto);
            var unitHosts = UnitHosts(classes);
            var unitUnknown = unitHosts.Where(h => !IsKnown(h)).ToList();
            bool onlyKnownHosts = unitHosts.Count > 0 && unitUnknown.Count == 0;

            if (dd.Has(StrStealer) && (net || dd.Has(FileWrite) || u.Has(ReadNet)))
            {
                var sf = Mk(Severity.Critical, 32, "Кража данных", classes,
                    $"Кража данных с компьютера (стилер) — {Simple(outer)}",
                    "В коде (часто в зашифрованных строках) есть пути к чужим данным: сессии Telegram (tdata, key_datas), токены Discord (Local Storage/leveldb), пароли и куки браузеров (Login Data, Local State), кошельки, аккаунты лаунчеров — и рядом сетевые запросы или работа с файлами. Так устроены стилеры, выдающие себя за мод.",
                    m, classes, StrStealer, Http, Socket, ReadNet, FileWrite, Process, StrUrl);
                ctx.Add(sf);
                reported.Add(outer);
                authFindings++;
                continue;
            }
            if (net && dd.Has(StrWebhook))
            {
                ctx.Add(Mk(Severity.Critical, 25, "Отправка данных на вебхук", classes,
                    $"Отправка данных на Discord-вебхук ({Simple(outer)})",
                    "В коде зашит адрес Discord-вебхука и есть сетевые запросы. Так моды-стилеры и «логгеры» сливают данные игрока (ник, IP, токены, HWID) владельцу.",
                    m, classes, StrWebhook, Http, ReadNet, HwidApi, SessionToken));
                reported.Add(outer);
                authFindings++;
                continue;
            }

            if (onlyKnownHosts && !hwid) continue;       // авторизация в известных сервисах (Microsoft, Spotify…)
            if (msAuth && !hwid && unitUnknown.Count == 0) continue;
            bool flow = crypto || dd.Has(Browse) || dd.Has(FileWrite) || dd.Has(Exit) || dd.Has(Base64);

            Severity sev = Severity.Info;
            string why = "";
            if (net && hwid && (strongAuth || crypto || unitUnknown.Count > 0))
            {
                sev = Severity.Critical;
                why = "Класс собирает идентификаторы компьютера (HWID: MAC-адрес, переменные окружения, серийники через wmic/oshi) и обращается к сети; рядом — строки лицензии/авторизации, криптография или неизвестный сервер. Так устроена привязка чит-клиента к компьютеру: мод авторизуется на сервере продавца и работает только по действующему ключу.";
            }
            else if (net && strongAuth && unitUnknown.Count > 0)
            {
                sev = Severity.Critical;
                why = "Класс отправляет запросы на собственный сервер (адрес не принадлежит известным сервисам) и оперирует лицензией/подпиской/авторизацией. Это внешняя авторизация: мод проверяет доступ на стороне своего сервера.";
            }
            else if (net && strongAuth && flow)
            {
                sev = Severity.Critical;
                why = "Класс ведёт полноценный обмен с сервером авторизации: сетевые запросы, строки лицензии/авторизации и работа с учётными данными (шифрование, сохранение токена в файл, открытие браузера для входа, завершение игры при отказе). Адрес сервера в открытом виде не найден — обычно его прячут шифрованием строк. Это внешняя авторизация клиента.";
            }
            else if (net && strongAuth)
            {
                sev = Severity.High;
                why = "Класс обращается к сети и оперирует лицензией/подпиской/авторизацией (по строкам или по названию класса). Адрес сервера в открытом виде не найден — обычно его прячут шифрованием строк.";
            }
            else if (net && hwid)
            {
                sev = Severity.High;
                why = "Класс собирает идентификаторы компьютера (HWID) и обращается к сети — типичная основа привязки к устройству и авторизации на внешнем сервере.";
            }
            else if (!net && LicenseClassRx.IsMatch(Simple(outer)) && (dd.Has(StrAuthStrong) || crypto || dd.Has(Exit) || classes.Count(c => LicenseClassRx.IsMatch(c.SimpleName)) > 1 || LicenseSiblings(m, outer) >= 2))
            {
                sev = Severity.Medium;
                why = "Есть подсистема лицензирования/авторизации (по названию класса и его содержимому), но сетевых обращений в ней нет — её вырезали при взломе или вынесли в другой модуль. Это следы платного клиента с внешней авторизацией.";
            }
            if (sev == Severity.Info) continue;
            if (sev == Severity.Medium) { stubs.Add(outer); continue; }        // следы вырезанной лицензии — одной карточкой ниже

            var f = Mk(sev, sev == Severity.Critical ? 28 : sev == Severity.High ? 14 : 5, "Внешняя авторизация", classes,
                $"Внешняя авторизация: {Simple(outer)}", why, m, classes, Http, Socket, ReadNet, HwidApi, StrHwid, StrAuthStrong, Crypto, Exit, Browse, StrUrl);
            if (unitUnknown.Count > 0) f.EvLines("Адреса серверов", unitUnknown.Take(12));
            if (hwid) f.EvLines("Сбор HWID", HwidEvidence(classes));
            ctx.Add(f);
            reported.Add(outer);
            authFindings++;
        }

        // ссылки на классы лицензии по имени (рефлексия), в т.ч. в расшифрованных строках: «com.water.LicenseValidator»
        var reflRefs = new List<string>();
        foreach (var c in m.OwnClasses)
            foreach (var mn in c.Methods)
                foreach (var s in mn.Strings)
                {
                    if (s.Length > 120 || !ReflClassRx.IsMatch(s)) continue;
                    string last = s[(s.LastIndexOf('.') + 1)..];
                    if (!LicenseClassRx.IsMatch(last)) continue;
                    string entry = $"{s}  [{c.SimpleName}.{mn.Name}{(mn.Decrypted.Contains(s) ? ", расшифровано" : "")}]";
                    if (reflRefs.Count < 20 && !reflRefs.Any(x => x.StartsWith(s + "  "))) reflRefs.Add(entry);
                }
        if (reflRefs.Count > 0 && authFindings == 0 && stubs.Count == 0)
            stubs.Add("(вызов по имени) " + reflRefs[0].Split("  [")[0].Replace('.', '/'));

        if (stubs.Count > 0)
            ctx.Add(new Finding
            {
                Severity = Severity.Medium, Category = "Авторизация", Analyzer = Name, Weight = 5, Signal = "Внешняя авторизация",
                Location = stubs[0],
                Title = $"Следы системы лицензии/авторизации без сетевой части ({Plural.Cls(stubs.Count)})",
                Why = "В моде есть подсистема лицензирования/защиты (по названиям и содержимому классов: лицензия, защищённые функции, проверка ключа), но сетевых обращений в ней нет — её вырезали при взломе («crack») или вынесли в другой модуль. Это следы платного клиента с внешней авторизацией.",
            }.EvLines("Классы", stubs.Take(30).Select(x => x.Replace('/', '.')))
             .EvLines("Обращения к классам лицензии по имени (рефлексия)", reflRefs));

        // уровень jar: классы лицензии есть, сеть есть, но в разных местах
        var licenseUnits = units.Where(x => LicenseClassRx.IsMatch(Simple(x.Unit)) && !reported.Contains(x.Unit)).Select(x => x.Unit).ToList();
        if (authFindings == 0 && stubs.Count == 0 && anyNet && !msAuth && licenseUnits.Count > 0 && (unknownHosts.Count > 0 || units.Any(x => x.D.Has(StrAuthStrong) || HwidReal(x.Classes))))
        {
            ctx.Add(new Finding
            {
                Severity = Severity.High, Category = "Авторизация", Analyzer = Name, Weight = 12, Signal = "Внешняя авторизация",
                Title = $"Подсистема авторизации/лицензии и сетевой клиент в моде ({Plural.Cls(licenseUnits.Count)})",
                Why = "В моде есть классы лицензии/авторизации и отдельно — код, работающий с сетью. Вместе это клиент внешней авторизации, разнесённый по классам.",
            }.EvLines("Классы авторизации", licenseUnits.Take(20).Select(x => x.Replace('/', '.')))
             .EvLines("Неизвестные адреса", unknownHosts.Take(12).SelectMany(kv => kv.Value.Take(1))));
        }

        // справка: все внешние адреса
        if (unknownHosts.Count > 0)
            ctx.Add(new Finding
            {
                Severity = Severity.Info, Category = "Авторизация", Analyzer = Name, Weight = 0,
                Title = $"Внешние адреса в коде мода ({unknownHosts.Count})",
                Why = "Адреса в строковых константах мода, не принадлежащие известным сервисам (Modrinth, GitHub, Mojang, Microsoft…). Справочно: куда мод может обращаться.",
            }.EvLines("Адреса", unknownHosts.Take(40).SelectMany(kv => kv.Value.Take(2))));
    }

    // ------------------------------------------------------------------ загрузка кода

    private void CodeLoaders(ScanContext ctx, ModModel m)
    {
        MethodNode? remote = null, dropper = null;
        if (m.IsLibraryJar) return;
        foreach (var c in m.OwnClasses)
            foreach (var mn in c.Methods)
            {
                var s = mn.Closure;
                bool netRead = s.Has(ReadNet) || (s.Has(Socket) && s.Has(Http)) || (s.Has(Http) && s.Has(Socket));
                bool netAny = netRead || s.Has(Http) || s.Has(Socket);
                if (remote is null && netAny && (s.Has(DefineClass) || (c.ExtendsClassLoader && s.Has(ReadNet))))
                    remote = mn;
                if (dropper is null && netAny && s.Has(FileWrite) && s.Has(Process))
                    dropper = mn;
            }

        // разнесённый загрузчик: сетевой класс ссылается на свой ClassLoader, который определяет классы
        (ClassNode Net, ClassNode Loader)? split = null;
        if (remote is null)
        {
            var loaders = m.OwnClasses.Where(c => c.ExtendsClassLoader || c.Methods.Any(x => x.Direct.Has(DefineClass))).ToList();
            foreach (var c in m.OwnClasses)
            {
                if (!c.Methods.Any(x => x.Closure.Has(ReadNet))) continue;
                var ld = loaders.FirstOrDefault(l => l != c && c.Cf.RefClasses.Contains(l.Name));
                if (ld is not null) { split = (c, ld); break; }
            }
        }

        if (remote is not null)
            ctx.Add(new Finding
            {
                Severity = Severity.Critical, Category = "Авторизация", Analyzer = Name, Weight = 32, Signal = "Загрузка кода из сети",
                Location = remote.Owner.Name,
                Title = $"Код загружается с сервера и определяется в рантайме ({remote.Owner.SimpleName})",
                Why = "Метод читает данные из сети и определяет из них классы (defineClass / собственный ClassLoader). В самом jar лежит только приёмник, а логика (обычно после авторизации) приходит с удалённого сервера и не видна при осмотре файла.",
            }.Ev("Где", Ev.Where(m, remote)).EvLines("Сеть и загрузка кода", Ev.Atoms(m, remote, Http, Socket, ReadNet, DefineClass, ClassLoader, Crypto, StrUrl))
             .EvLines("Адреса и строки класса (в т.ч. расшифрованные)", UnitStrings(m, remote.Owner.Outer)));
        else if (split is not null)
            ctx.Add(new Finding
            {
                Severity = Severity.Critical, Category = "Авторизация", Analyzer = Name, Weight = 30, Signal = "Загрузка кода из сети",
                Location = split.Value.Net.Name,
                Title = $"Сетевой клиент передаёт данные своему загрузчику классов ({split.Value.Net.SimpleName} → {split.Value.Loader.SimpleName})",
                Why = $"Класс {split.Value.Net.SimpleName} читает данные из сети и использует класс {split.Value.Loader.SimpleName} — собственный загрузчик классов (extends ClassLoader / defineClass). Так подгружают код с сервера после авторизации.",
            }.Ev("Сетевой класс", split.Value.Net.Name.Replace('/', '.')).Ev("Загрузчик", split.Value.Loader.Name.Replace('/', '.') + (split.Value.Loader.Cf.Super is { } sp ? " extends " + sp.Replace('/', '.') : "")));

        if (dropper is not null)
        {
            var reach = m.ClosureMethods(dropper);
            var urls = reach.SelectMany(x => x.Hits.TryGetValue(StrUrl, out var l) ? l : new List<string>()).ToList();
            bool hidden = urls.Count == 0 || urls.All(x => x.EndsWith("(расшифровано)"));
            bool updater = reach.Any(x => x.Name.Contains("update", StringComparison.OrdinalIgnoreCase) || x.Owner.SimpleName.Contains("update", StringComparison.OrdinalIgnoreCase)
                                          || x.Strings.Any(s => s.Contains("update", StringComparison.OrdinalIgnoreCase)));
            bool stealer = reach.Any(x => x.Direct.Has(StrStealer)) || (m.Units.TryGetValue(dropper.Owner.Outer, out var dcls) && dcls.Any(c => c.Methods.Any(x => x.Direct.Has(StrStealer))));
            bool crit = stealer || (hidden && !updater);
            ctx.Add(new Finding
            {
                Severity = crit ? Severity.Critical : Severity.Medium, Category = "Авторизация", Analyzer = Name, Weight = crit ? 32 : 5, Signal = "Скачивание и запуск файла",
                Location = dropper.Owner.Name,
                Title = crit ? $"Мод скачивает файл из сети и запускает его ({dropper.Owner.SimpleName})"
                             : $"Мод скачивает файлы и запускает процессы — похоже на автообновление/загрузку компонентов ({dropper.Owner.SimpleName})",
                Why = crit
                    ? "Метод читает данные по сети, записывает их в файл и запускает процесс ОС (ProcessBuilder / Runtime.exec), а адрес спрятан (зашифрован или собирается в рантайме). Это загрузчик внешней программы (дроппер): что именно будет запущено, решает удалённый сервер. Для мода к игре — недопустимо."
                    : "Мод скачивает файлы и запускает процессы ОС, но адрес виден открыто и/или это похоже на штатное автообновление или загрузку компонентов (браузерный движок, нативные библиотеки). Проверьте адрес и что запускается.",
            }.Ev("Где", Ev.Where(m, dropper)).EvLines("Сеть, запись и запуск", Ev.Atoms(m, dropper, Http, ReadNet, FileWrite, Process, StrExe, StrUrl))
             .EvLines("Адреса и строки класса (в т.ч. расшифрованные)", UnitStrings(m, dropper.Owner.Outer).Concat(urls).Distinct().Take(20)));
        }
    }

    // ------------------------------------------------------------------ помощники

    /// <summary>Сколько ещё классов лицензии/защиты лежит в том же пакете (LicenseGuard, LicenseConfig, ProtectedContent…).</summary>
    private static int LicenseSiblings(ModModel m, string outer)
    {
        int slash = outer.LastIndexOf('/');
        string pkg = slash > 0 ? outer[..slash] : "";
        return m.Units.Keys.Count(k => k != outer && (slash > 0 ? k.StartsWith(pkg + "/") && k.LastIndexOf('/') == slash : !k.Contains('/')) && LicenseClassRx.IsMatch(Simple(k)));
    }

    /// <summary>Адреса, исполняемые файлы и пути к данным, найденные в строках (включая расшифрованные) логической единицы.</summary>
    private static IEnumerable<string> UnitStrings(ModModel m, string outer)
    {
        if (!m.Units.TryGetValue(outer, out var cls)) yield break;
        var seen = new HashSet<string>();
        foreach (var c in cls)
            foreach (var mn in c.Methods)
                foreach (var a in new[] { StrUrl, StrExe, StrStealer, StrWebhook })
                    if (mn.Hits.TryGetValue(a, out var l))
                        foreach (var x in l) if (seen.Add(x)) yield return $"{x}  [{c.SimpleName}.{mn.Name}]";
    }

    private static bool Net(AtomSet u) => u.Has(Http) || u.Has(Socket) || u.Has(ReadNet);

    /// <summary>Реальный сбор HWID: MAC-адрес/oshi либо getenv вместе с «железными» строками.</summary>
    private static bool HwidReal(List<ClassNode> classes)
    {
        foreach (var c in classes)
            foreach (var mn in c.Methods)
            {
                if (!mn.Hits.TryGetValue(HwidApi, out var l)) continue;
                if (l.Any(x => !x.EndsWith("System.getenv"))) return true;
                if (mn.Strings.Any(s => s is "COMPUTERNAME" or "PROCESSOR_IDENTIFIER" or "PROCESSOR_ARCHITECTURE" or "PROCESSOR_LEVEL" or "PROCESSOR_REVISION" or "NUMBER_OF_PROCESSORS" or "USERDOMAIN" or "HOSTNAME")) return true;
            }
        return false;
    }

    private static IEnumerable<string> HwidEvidence(List<ClassNode> classes)
    {
        foreach (var c in classes)
            foreach (var mn in c.Methods)
            {
                if (mn.Hits.TryGetValue(HwidApi, out var l)) foreach (var x in l) yield return $"{x}  [{c.SimpleName}.{mn.Name}]";
                if (mn.Hits.TryGetValue(StrHwid, out var s)) foreach (var x in s) yield return $"{x}  [{c.SimpleName}.{mn.Name}]";
            }
    }

    private static List<string> UnitHosts(List<ClassNode> classes)
    {
        var res = new List<string>();
        foreach (var c in classes) foreach (var mn in c.Methods) foreach (var s in mn.Strings) foreach (var (h, _) in Hosts(s)) if (!res.Contains(h)) res.Add(h);
        return res;
    }

    public static IEnumerable<(string Host, string Url)> Hosts(string s)
    {
        if (s.Length > 2000) yield break;
        bool any = false;
        foreach (Match mt in UrlRx.Matches(s)) { any = true; yield return (mt.Groups["host"].Value.ToLowerInvariant(), mt.Value.Length > 140 ? mt.Value[..140] + "…" : mt.Value); }
        if (!any)
        {
            var hm = HostOnlyRx.Match(s.Trim());
            if (hm.Success && !s.Contains(' ')) yield return (hm.Groups["host"].Value.ToLowerInvariant(), s.Trim());
        }
    }

    public static bool IsKnown(string host)
    {
        host = host.ToLowerInvariant();
        foreach (var k in KnownHosts) if (host == k || host.EndsWith("." + k)) return true;
        return host.StartsWith("192.168.") || host.StartsWith("10.") || host.StartsWith("127.");
    }

    private static string Simple(string n) => n[(n.LastIndexOf('/') + 1)..];

    private Finding Mk(Severity sev, double w, string signal, List<ClassNode> classes, string title, string why, ModModel m, List<ClassNode> cls, params int[] atoms)
    {
        var f = new Finding
        {
            Severity = sev, Category = "Авторизация", Analyzer = Name, Weight = w, Signal = signal,
            Location = classes[0].Outer, Title = title, Why = why,
        };
        // по атому — лучший метод-пример
        var lines = new List<string>();
        foreach (var a in atoms)
        {
            var ms = cls.SelectMany(c => c.Methods).ToList();
            var mn = ms.FirstOrDefault(x => x.Direct.Has(a)) ?? ms.FirstOrDefault(x => x.Closure.Has(a));
            if (mn is null) continue;
            lines.Add($"{m.Explain(mn, a)}  [{mn.Owner.SimpleName}.{mn.Name}]");
        }
        f.EvLines("Признаки", lines);
        f.Ev("Классы", string.Join("\n", cls.Select(c => c.Name.Replace('/', '.')).Take(20)));
        return f;
    }
}
