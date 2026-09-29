using ModScanner.Core;
using ModScanner.Report;
using static ModScanner.Analysis.Vocab;

namespace ModScanner.Analysis;

/// <summary>
/// Манипуляция сетевыми пакетами — намеренное ухудшение пинга/задержка:
///   * FakeLag / Blink — исходящие пакеты отменяются, копятся в очереди и отправляются позже пачкой;
///   * задержка входящих (Backtrack / FakeLag in) — входящие пакеты придерживаются и обрабатываются позже;
///   * PingSpoof — придерживаются ответы KeepAlive/Pong, по которым сервер меряет пинг;
///   * задержка в конвейере Netty — свой обработчик канала копит и откладывает запись/чтение.
/// Просто перехват пакетов (шина событий, отмена, логгер, ответ на KeepAlive своим ботом) задержкой
/// не является и не наказывается: нужны удержание (очередь пакетов/таймер) и отложенная отправка.
/// </summary>
internal sealed class PacketAnalyzer : IAnalyzer
{
    public string Name => "Пакеты";

    private static readonly string[] FlowTargets =
    {
        "Connection.send", "Connection.doSendPacket", "Connection.channelRead0", "Connection.genericsFtw", "ClientCommonPacketListenerImpl.send",
        "ClientCommonPacketListenerImpl.handleKeepAlive", "ClientCommonPacketListenerImpl.handlePing", "ClientConnection.send", "ClientConnection.channelRead0",
        "ClientConnection.handlePacket", "ClientConnection.sendInternal", "ClientCommonNetworkHandler.sendPacket", "ClientCommonNetworkHandler.onKeepAlive",
        "ClientCommonNetworkHandler.onPing",
    };

    private static readonly HashSet<string> KeepAliveTypes = new(StringComparer.Ordinal)
    {
        "ServerboundKeepAlivePacket", "ClientboundKeepAlivePacket", "ServerboundPongPacket", "ClientboundPingPacket",
        "KeepAliveC2SPacket", "KeepAliveS2CPacket", "CommonPongC2SPacket", "CommonPingS2CPacket",
    };

    // пакеты, удержание которых даёт лаг: общий Packet, движение, бой, KeepAlive/Pong, подтверждения
    private static bool LagPacket(string simple) =>
        simple == "Packet" || KeepAliveTypes.Contains(simple) || simple.StartsWith("ServerboundMovePlayerPacket") || simple.StartsWith("PlayerMoveC2SPacket")
        || simple is "ServerboundInteractPacket" or "ServerboundSwingPacket" or "ServerboundPlayerActionPacket" or "ServerboundUseItemOnPacket" or "ServerboundUseItemPacket"
            or "ServerboundPlayerInputPacket" or "ServerboundClientTickEndPacket" or "ServerboundAcceptTeleportationPacket" or "ServerboundPlayerCommandPacket"
            or "PlayerInteractEntityC2SPacket" or "HandSwingC2SPacket" or "PlayerActionC2SPacket" or "PlayerInteractBlockC2SPacket" or "ClientTickEndC2SPacket"
            or "TeleportConfirmC2SPacket" or "ClientCommandC2SPacket" or "PlayerInputC2SPacket";

    private static readonly HashSet<string> CancelNames = new(StringComparer.Ordinal) { "cancel", "setCancelled", "setCanceled", "cancelEvent", "setCancel" };

    public void Run(ScanContext ctx)
    {
        var m = ctx.Model;
        var flowHooks = m.Hooks.Where(h => h.Targets(FlowTargets)).ToList();
        bool jarIntercepts = flowHooks.Count > 0;
        var cancelers = new HashSet<MethodNode>(m.AllMethods.Where(CallsCancel));

        foreach (var (outer, classes) in m.Units)
        {
            var methods = classes.SelectMany(c => c.Methods).ToList();
            AtomSet d = default, u = default;
            foreach (var mn in methods) { d.Or(mn.Direct); u.Or(mn.Closure); }
            if (!u.Has(PacketType) && !u.Has(SendPacket) && !u.Has(AutoRead)) continue;

            var holders = classes.SelectMany(c => c.PacketCollections.Select(p => $"{c.SimpleName}.{p}")).ToList();
            var held = classes.SelectMany(c => c.HeldPacketTypes).ToHashSet();
            bool hold = holders.Count > 0 && held.Any(LagPacket);
            bool cancel = u.Has(Cancel) || methods.Any(x => cancelers.Contains(x) || x.Callees.Any(cancelers.Contains));
            bool timed = d.Has(Clock) || d.Has(Delay);
            bool resendOut = u.Has(SendPacket);
            bool resendIn = u.Has(HandlePacket);
            bool netty = classes.Any(c => c.IsNettyHandler);
            string unit = outer[(outer.LastIndexOf('/') + 1)..];

            // PingSpoof: удерживаются именно KeepAlive/Pong (очередь этих типов либо метод, где KeepAlive + отмена/таймер/очередь)
            MethodNode? pingM = methods.FirstOrDefault(x => x.Direct.Has(KeepAlive)
                && (x.Closure.Has(Delay) || ((x.Closure.Has(Cancel) || cancelers.Contains(x)) && (x.Closure.Has(QueueAdd) || x.Closure.Has(Clock)))));
            bool pingHold = hold && held.Count > 0 && held.All(KeepAliveTypes.Contains);
            if (pingHold || (pingM is not null && !netty))
            {
                ctx.Add(Mk(Severity.Critical, 28, "PingSpoof", outer,
                    $"PingSpoof — задержка ответов KeepAlive/Pong ({unit})",
                    "Код перехватывает пакеты KeepAlive / Ping-Pong (по ним сервер измеряет пинг) и придерживает их: копит в очереди, откладывает по таймеру или отменяет с последующей отправкой. Сервер видит завышенный пинг, а античит даёт игроку больше поблажек на лаг.",
                    m, methods, holders, pingM, KeepAlive, Cancel, QueueAdd, Clock, Delay, SendPacket));
                continue;
            }
            if (hold && resendOut && cancel)
            {
                ctx.Add(Mk(Severity.Critical, 28, "FakeLag / Blink", outer,
                    $"FakeLag / Blink — исходящие пакеты придерживаются и отправляются позже ({unit})",
                    "Код отменяет отправку пакетов игры, складывает их в собственную очередь и затем отправляет пачкой (по таймеру или по выключению). Для сервера игрок «замирает», а потом телепортируется — искусственный лаг, которым уходят от ударов, обманывают античит и получают преимущество в бою.",
                    m, methods, holders, null, Cancel, QueueAdd, SendPacket, Clock, Delay, MovePacket));
                continue;
            }
            if (hold && resendIn && cancel)
            {
                ctx.Add(Mk(Severity.Critical, 26, "Задержка входящих пакетов", outer,
                    $"Задержка входящих пакетов (Backtrack / FakeLag) — {unit}",
                    "Код перехватывает входящие пакеты, копит их и обрабатывает позже (Packet.handle / channelRead). Игрок видит противников «в прошлом» и бьёт по устаревшим позициям — Backtrack; сервер получает ответы с задержкой.",
                    m, methods, holders, null, Cancel, QueueAdd, HandlePacket, Clock, Delay));
                continue;
            }
            if (netty && (d.Has(Delay) || (d.Has(QueueAdd) && d.Has(Clock))) && (u.Has(PacketType) || resendOut))
            {
                bool ka = d.Has(KeepAlive);
                ctx.Add(Mk(Severity.Critical, 26, "FakeLag / Blink", outer,
                    $"Задержка пакетов в конвейере Netty ({unit}){(ka ? " — с учётом KeepAlive/Pong" : "")}",
                    "Собственный обработчик канала Netty (встраивается в соединение с сервером) складывает пакеты в очередь и отпускает их по времени (schedule / замер времени). Это искусственная задержка соединения на сетевом уровне: FakeLag" + (ka ? "; отдельно обрабатываются KeepAlive/Pong — пакеты, по которым сервер меряет пинг." : "."),
                    m, methods, holders, null, QueueAdd, Clock, Delay, SendPacket, HandlePacket, KeepAlive, Pipeline));
                continue;
            }
            if (d.Has(AutoRead) && timed && !m.IsLibraryJar)
            {
                ctx.Add(Mk(Severity.High, 12, "FakeLag / Blink", outer,
                    $"Остановка чтения соединения по таймеру ({unit})",
                    "Код выключает автоматическое чтение канала (setAutoRead) и управляет им по времени — входящие пакеты перестают обрабатываться, что создаёт искусственный лаг.",
                    m, methods, holders, null, AutoRead, Clock, Delay));
                continue;
            }
            // совокупность признаков без явной коллекции пакетов (обфускация стёрла сигнатуры)
            if (!hold && jarIntercepts && !m.IsLibraryJar && d.Has(PacketType) && d.Has(QueueAdd) && (resendOut || resendIn) && timed && cancel
                && classes.Any(c => c.Cf.Fields.Any(f => f.Desc.StartsWith("Ljava/util/"))))
            {
                ctx.Add(Mk(Severity.High, 12, "FakeLag / Blink", outer,
                    $"Накопление и отложенная отправка пакетов (по совокупности признаков) — {unit}",
                    "Код отменяет пакеты, складывает объекты в коллекцию, замеряет время и позже отправляет/обрабатывает пакеты. Тип коллекции скрыт (обфускация стёрла сигнатуры), но набор действий соответствует FakeLag/Blink.",
                    m, methods, holders, null, Cancel, QueueAdd, SendPacket, HandlePacket, Clock, Delay, PacketType));
            }
        }

        if (jarIntercepts && !ctx.Findings.Any(f => f.Analyzer == Name))
            ctx.Add(new Finding
            {
                Severity = Severity.Info, Category = "Пакеты", Analyzer = Name, Weight = 0,
                Title = $"Перехват сетевых пакетов игры ({flowHooks.Count} инъекций)",
                Why = "Мод перехватывает отправку/приём пакетов (обычно — шина событий для модулей). Сам по себе перехват не ухудшает пинг; признаков накопления и задержки пакетов не найдено.",
            }.EvLines("Инъекции", flowHooks.Take(15).Select(h => h.Describe())));
    }

    /// <summary>Метод отменяет событие своей шины: вызывает cancel()/setCancelled() у собственного класса.</summary>
    private static bool CallsCancel(MethodNode mn)
    {
        var cf = mn.Owner.Cf;
        foreach (var ins in mn.Mi.Insns)
            if (Bytecode.IsInvoke(ins.Op) && ins.Op != Bytecode.INVOKEDYNAMIC)
            {
                var r = cf.Member(ins.Operand);
                if (r is not null && CancelNames.Contains(r.Name) && !GameNames.IsGame(r.Owner) && !r.Owner.StartsWith("java/")) return true;
            }
        return false;
    }

    private Finding Mk(Severity sev, double w, string signal, string outer, string title, string why, ModModel m, List<MethodNode> methods, List<string> holders, MethodNode? focus, params int[] atoms)
    {
        var f = new Finding { Severity = sev, Category = "Пакеты", Analyzer = Name, Weight = w, Signal = signal, Location = outer, Title = title, Why = why };
        if (focus is not null) f.Ev("Где", Ev.Where(m, focus));
        if (holders.Count > 0) f.EvLines("Очереди пакетов (поля)", holders.Take(10));
        var lines = new List<string>();
        foreach (var a in atoms)
        {
            var mn = (focus is not null && focus.Closure.Has(a) ? focus : null) ?? methods.FirstOrDefault(x => x.Direct.Has(a)) ?? methods.FirstOrDefault(x => x.Closure.Has(a));
            if (mn is null) continue;
            lines.Add($"{m.Explain(mn, a)}  [{mn.Owner.SimpleName}.{mn.Name}]");
        }
        f.EvLines("Признаки", lines);
        var hooks = methods.Select(x => x.Owner).Distinct().SelectMany(c => c.Hooks).Take(6).Select(h => h.Describe()).ToList();
        if (hooks.Count > 0) f.EvLines("Инъекции класса", hooks);
        return f;
    }
}
