using ModScanner.Core;
using ModScanner.Report;
using static ModScanner.Analysis.Vocab;

namespace ModScanner.Analysis;

/// <summary>
/// Боевые функции: TriggerBot, KillAura, HitBox, Reach, AimAssist. Работает по обращениям к API игры
/// (промежуточные имена и имена Mojang мод переименовать не может) и по Mixin-инъекциям в методы игры.
/// Каждое правило — сочетание «атомов» в одном методе с учётом вызываемых им методов мода
/// (логика чита часто разнесена: модуль → утилита целей → утилита атаки).
/// </summary>
internal sealed class CombatAnalyzer : IAnalyzer
{
    public string Name => "Бой";

    // методы игры, которые вызываются только по клику атаки игрока: код в их инъекциях — реакция на клик, а не автоатака.
    // handleKeybinds сюда НЕ входит: он выполняется каждый тик, и инъекция в него — обычное место для триггербота.
    private static readonly string[] UserAttackFlow =
    {
        "Minecraft.startAttack", "Minecraft.continueAttack", "MultiPlayerGameMode.attack",
        "MinecraftClient.doAttack", "MinecraftClient.handleBlockBreaking", "ClientPlayerInteractionManager.attackEntity",
    };

    private static readonly string[] HitboxTargets =
    {
        "Entity.getBoundingBox", "Entity.getPickRadius", "Entity.getTargetingMargin", "Entity.makeBoundingBox", "Entity.calculateBoundingBox",
    };
    private static readonly string[] DimensionTargets = { "Entity.getDimensions", "EntityDimensions.makeBoundingBox", "EntityDimensions.getBoxAt" };
    private static readonly string[] PickTargets =
    {
        "ProjectileUtil.getEntityHitResult", "GameRenderer.pick", "ProjectileUtil.getEntityCollision", "ProjectileUtil.raycast",
        "GameRenderer.findCrosshairTarget", "GameRenderer.updateCrosshairTarget",
    };
    private static readonly string[] HitboxAt = { "AABB.inflate", "Entity.getPickRadius", "Entity.getBoundingBox", "Box.expand", "Entity.getTargetingMargin" };
    private static readonly string[] ReachTargets =
    {
        "Player.entityInteractionRange", "Player.isWithinEntityInteractionRange", "Player.isWithinAttackRange",
        "PlayerEntity.getEntityInteractionRange", "PlayerEntity.canInteractWithEntity", "PlayerEntity.canInteractWithEntityIn", "PlayerEntity.canAttackEntityIn",
        "MultiPlayerGameMode.getPickRange", "ClientPlayerInteractionManager.getReachDistance",
    };
    private static readonly string[] MouseTurnTargets = { "MouseHandler.turnPlayer", "Mouse.updateMouse", "Entity.turn", "Entity.changeLookDirection" };

    private static readonly string[] ReachAt =
    {
        "Player.entityInteractionRange", "PlayerEntity.getEntityInteractionRange", "Player.isWithinEntityInteractionRange",
        "MultiPlayerGameMode.getPickRange", "ClientPlayerInteractionManager.getReachDistance",
    };

    public void Run(ScanContext ctx)
    {
        var m = ctx.Model;
        HookRules(ctx, m);
        CodeRules(ctx, m);
    }

    // ------------------------------------------------------------------ Mixin-инъекции

    private void HookRules(ScanContext ctx, ModModel m)
    {
        var hitboxHooks = new List<Hook>();
        var dimHooks = new List<Hook>();
        var reachHooks = new List<Hook>();
        var inertHitbox = new List<Hook>();
        var aimHooks = new List<Hook>();
        foreach (var h in m.Hooks)
        {
            var body = h.Handler.Closure;
            // AimAssist через обработку мыши: к повороту камеры примешивается доворот на цель
            if (h.Targets(MouseTurnTargets) && (body.Has(CrosshairEntity) || (body.Has(EntityList) && body.Has(PlayerTarget))) && body.Has(AimMath) && body.Has(TargetPos) && AimsAtEntity(m, h.Handler))
                aimHooks.Add(h);
            if (!h.ChangesValue && !(h.Cancellable && h.Handler.Mi.Desc.Contains("CallbackInfoReturnable"))) continue;
            // инъекция, способная подменить хитбокс, но без логики внутри: логику вырезали при взломе или подгружают отдельно
            if (h.Targets(HitboxTargets) && !body.Has(BoxGrow) && !h.Targets("Entity.getPickRadius", "Entity.getTargetingMargin") && h.Kind != "ModifyConstant")
            {
                if (h.Kind is "ModifyReturnValue" or "WrapOperation" or "Redirect" || h.Cancellable) inertHitbox.Add(h);
                continue;
            }
            if (!h.ChangesValue) continue;
            if (h.Targets(HitboxTargets) && (body.Has(BoxGrow) || h.Targets("Entity.getPickRadius", "Entity.getTargetingMargin") || h.Kind == "ModifyConstant"))
                hitboxHooks.Add(h);
            else if (h.Targets(PickTargets) && h.At(HitboxAt))
                hitboxHooks.Add(h);
            else if (h.Targets(DimensionTargets) && body.Has(BoxGrow))
                dimHooks.Add(h);

            if (h.Targets(ReachTargets))
                reachHooks.Add(h);
            else if (h.Targets(PickTargets) && !h.At(HitboxAt)
                     && (h.At(ReachAt) || h.Constants.Any(c => c is 3.0 or 9.0 or 4.5 or 20.25) || h.Kind is "ModifyVariable" or "ModifyArg" && h.AtKeys.Count == 0))
                reachHooks.Add(h);
        }

        if (hitboxHooks.Count > 0)
            ctx.Add(new Finding
            {
                Severity = Severity.Critical, Category = "Бой", Analyzer = Name, Weight = 30, Signal = "HitBox",
                Location = hitboxHooks[0].Mixin.Name,
                Title = "HitBox — хитбоксы сущностей подменяются инъекцией в код игры",
                Why = "Mixin перехватывает метод игры, который отдаёт область попадания сущности (getBoundingBox / getPickRadius) или используется в поиске цели под прицелом, и возвращает изменённую — увеличенную — область. Прицел и удар начинают «цеплять» врага, когда игрок промахивается: это классический HitBox/Hitboxes.",
            }
            .EvLines("Инъекции", hitboxHooks.Take(12).Select(h => h.Describe()))
            .EvLines("Что делает обработчик", hitboxHooks.Take(3).SelectMany(h => Ev.Atoms(m, h.Handler, BoxGrow, GetBox, SetReturn, KeyPress)).Distinct().Take(12)));

        if (inertHitbox.Count > 0 && hitboxHooks.Count == 0)
        {
            var f = new Finding
            {
                Severity = Severity.High, Category = "Бой", Analyzer = Name, Weight = 14, Signal = "HitBox",
                Location = inertHitbox[0].Mixin.Name,
                Title = "HitBox — инъекция в расчёт хитбокса сущности (логика обработчика вырезана или подгружается отдельно)",
                Why = "Mixin встраивается в метод игры, отдающий область попадания сущности (getBoundingBox), способом, позволяющим подменить результат, но сам обработчик сейчас ничего не меняет. Так выглядит взломанный или «защищённый» чит: точка встраивания HitBox осталась, а логика вырезана либо приходит отдельно (с сервера, из зашифрованного ресурса, из нативной библиотеки). Честному моду перехватывать хитбокс чужих сущностей незачем.",
            }
            .EvLines("Инъекции", inertHitbox.Take(12).Select(h => h.Describe()))
            .EvLines("Тело обработчика", inertHitbox.Take(3).Select(h => $"{m.Label(h.Handler)}: {h.Handler.Mi.Insns.Count} инструкций, обращений к API игры: {h.Handler.Closure.Ids().Count()}"));
            f.Tags.Add("inert");
            ctx.Add(f);
        }

        if (aimHooks.Count > 0)
            ctx.Add(new Finding
            {
                Severity = Severity.Critical, Category = "Бой", Analyzer = Name, Weight = 28, Signal = "AimAssist",
                Location = aimHooks[0].Mixin.Name,
                Title = "AimAssist — к повороту камеры мышью примешивается доворот на цель",
                Why = "Mixin встраивается в обработку поворота мыши (MouseHandler.turnPlayer / Entity.turn) и при этом ищет цель (сущности мира / под прицелом) и считает угол до неё. Камера «прилипает» к противнику, хотя двигает её игрок, — это AimAssist.",
            }
            .EvLines("Инъекции", aimHooks.Take(12).Select(h => h.Describe()))
            .EvLines("Что делает обработчик", aimHooks.Take(3).SelectMany(h => Ev.Atoms(m, h.Handler, EntityList, Crosshair, Raycast, AimMath, TargetPos, Rotate, Turn, TargetCheck)).Distinct().Take(14)));

        if (dimHooks.Count > 0 && hitboxHooks.Count == 0)
            ctx.Add(new Finding
            {
                Severity = Severity.High, Category = "Бой", Analyzer = Name, Weight = 12, Signal = "HitBox",
                Location = dimHooks[0].Mixin.Name,
                Title = "HitBox — размеры сущностей меняются инъекцией",
                Why = "Mixin меняет размеры сущностей (getDimensions / makeBoundingBox) и строит по ним увеличенную область. Так расширяют хитбоксы целей. Бывает и у модов на позы игрока — проверьте, к каким сущностям применяется.",
            }.EvLines("Инъекции", dimHooks.Take(12).Select(h => h.Describe())));

        if (reachHooks.Count > 0)
            ctx.Add(new Finding
            {
                Severity = Severity.Critical, Category = "Бой", Analyzer = Name, Weight = 30, Signal = "Reach",
                Location = reachHooks[0].Mixin.Name,
                Title = "Reach — дальность удара/взаимодействия меняется инъекцией в код игры",
                Why = "Mixin перехватывает метод игры, отвечающий за дальность взаимодействия с сущностями (entityInteractionRange / isWithinEntityInteractionRange / поиск цели под прицелом), и подменяет значение — дальность, константу или аргумент. Игрок достаёт врага дальше ванильных 3 блоков.",
            }
            .EvLines("Инъекции", reachHooks.Take(12).Select(h => h.Describe()))
            .EvLines("Что делает обработчик", reachHooks.Take(3).SelectMany(h => Ev.Atoms(m, h.Handler, RangeRead, RangeAttr, Distance, SetReturn, KeyPress)).Distinct().Take(12)));
    }

    // ------------------------------------------------------------------ код

    private sealed class Hit
    {
        public MethodNode M = null!;
        public int Score;
    }

    private void CodeRules(ScanContext ctx, ModModel m)
    {
        // методы, выполняемые в ответ на клик атаки игрока (инъекции в startAttack и то, что они вызывают)
        var userFlow = new HashSet<MethodNode>();
        foreach (var h in m.Hooks.Where(h => h.Targets(UserAttackFlow)))
            Reach(h.Handler, userFlow);

        var trigger = new Dictionary<string, Hit>(StringComparer.Ordinal);
        var aura = new Dictionary<string, Hit>(StringComparer.Ordinal);
        var reach = new Dictionary<string, Hit>(StringComparer.Ordinal);
        var hitbox = new Dictionary<string, Hit>(StringComparer.Ordinal);
        var hitboxAim = new Dictionary<string, Hit>(StringComparer.Ordinal);
        var aim = new Dictionary<string, Hit>(StringComparer.Ordinal);

        foreach (var c in m.Classes.Values)
            foreach (var mn in c.Methods)
            {
                var s = mn.Closure;
                if (s.IsEmpty) continue;
                bool attacks = AttacksInCode(s);

                // TriggerBot: цель под прицелом (или собственный луч прицела по сущностям) + удар кодом
                bool aimTarget = s.Has(Crosshair) || (s.Has(Raycast) && s.Has(EntityList));
                if (attacks && aimTarget && !userFlow.Contains(mn))
                    Keep(trigger, c.Outer, mn, Score(mn, Attack, StartAttack, Crosshair, Raycast, KeyPress, TargetCheck));

                // KillAura: перебор сущностей вокруг + отбор + удар; если цель выбирается собственным лучом прицела без доворота — это TriggerBot
                if (attacks && s.Has(EntityList) && s.Any(Distance, Rotate, RangeRead, TargetCheck) && (s.Has(Rotate) || !s.Has(Raycast)))
                    Keep(aura, c.Outer, mn, Score(mn, Attack, StartAttack, EntityList, Distance, Rotate, TargetCheck));

                // AimAssist: цель (перебор сущностей / под прицелом) + угол на неё + запись поворота игрока, без удара кодом.
                // Если удар тоже в коде — это доворот ауры/триггербота, он уже в их находках.
                bool aimCandidate = s.Has(CrosshairEntity) || (s.Has(EntityList) && s.Has(PlayerTarget) && s.Any(Distance, RangeRead)) || (s.Has(Raycast) && s.Has(EntityList) && s.Has(PlayerTarget));
                if (!c.IsLibrary && s.Has(LocalRotate) && aimCandidate && s.Has(AimMath) && s.Has(TargetPos) && AimsAtEntity(m, mn)
                    && (!attacks || Short(c.Outer).Contains("aim", StringComparison.OrdinalIgnoreCase)))
                    Keep(aim, c.Outer, mn, Score(mn, Rotate, Turn, AimMath, EntityList, Crosshair, TargetPos) + (int)NameBonus(c.Outer, "aim"));

                if (s.Has(AttrSet) && s.Has(RangeAttr))
                    Keep(reach, c.Outer, mn, Score(mn, AttrSet, RangeAttr));

                if (s.Has(SetBox) && s.Has(BoxGrow))
                    Keep(hitbox, c.Outer, mn, Score(mn, SetBox, BoxGrow, EntityList) + (s.Has(EntityList) ? 10 : 0));
                else if (attacks && s.Has(GetBox) && s.Has(BoxGrow) && s.Any(Raycast, Crosshair))
                    Keep(hitboxAim, c.Outer, mn, Score(mn, GetBox, BoxGrow, Raycast, Attack));
            }

        foreach (var (unit, hit) in trigger)
        {
            var mn = hit.M;
            ctx.Add(new Finding
            {
                Severity = Severity.Critical, Category = "Бой", Analyzer = Name, Weight = 30 + NameBonus(unit, "trigger"), Signal = "TriggerBot",
                Location = mn.Owner.Name,
                Title = $"TriggerBot — автоатака по цели под прицелом ({Short(unit)})",
                Why = "Код сам определяет сущность под прицелом (hitResult / crosshairPickEntity / EntityHitResult) и сам наносит удар (MultiPlayerGameMode.attack / startAttack / нажатие клавиши атаки кодом). Удар наносит программа, а не игрок — это триггербот. Инъекции, срабатывающие на клик игрока, исключены.",
            }
            .Ev("Где", Ev.Where(m, mn))
            .EvLines("Цель и удар (цепочка вызовов внутри мода)", Ev.Atoms(m, mn, Crosshair, Raycast, EntityList, Attack, StartAttack, KeyAttack, KeyPress, MouseEmu, TargetCheck, Distance, Swing)));
        }

        foreach (var (unit, hit) in aura)
        {
            var mn = hit.M;
            ctx.Add(new Finding
            {
                Severity = Severity.Critical, Category = "Бой", Analyzer = Name, Weight = 30 + NameBonus(unit, "aura"), Signal = "KillAura",
                Location = mn.Owner.Name,
                Title = $"KillAura — перебор сущностей вокруг и атака ({Short(unit)})",
                Why = "Код перебирает сущности мира, отбирает цель по дистанции/углу/здоровью и сам атакует её (MultiPlayerGameMode.attack / пакет атаки / клик кодом), часто с доворотом камеры. Игрок так не бьёт — это аура.",
            }
            .Ev("Где", Ev.Where(m, mn))
            .EvLines("Перебор, отбор и удар", Ev.Atoms(m, mn, EntityList, Distance, TargetCheck, Rotate, RangeRead, Attack, StartAttack, KeyPress, Swing)));
        }

        // AimAssist, развязанный через состояние: один метод считает угол на сущность и сохраняет его (в поле или в
        // «менеджер поворотов» вида Rotations.rotate(yaw, pitch)), другой — поворачивает локального игрока.
        var rotationClasses = m.OwnClasses.Where(c => c.Methods.Any(x => x.Direct.Has(LocalRotate))).ToHashSet();
        foreach (var (outer, classes) in m.Units)
        {
            if (aim.ContainsKey(outer) || trigger.ContainsKey(outer) || aura.ContainsKey(outer) || classes.All(c => c.IsLibrary)) continue;
            var methods = classes.SelectMany(c => c.Methods).ToList();
            // выбор цели-игрока и расчёт угла на сущность — в одном потоке вызовов
            var selM = methods.FirstOrDefault(x => (x.Closure.Has(CrosshairEntity) || (x.Closure.Has(EntityList) && x.Closure.Has(PlayerTarget) && x.Closure.Any(Distance, RangeRead, TargetCheck))) && AimsAtEntity(m, x));
            if (selM is null) continue;
            var aimM = AimMethods(m, selM).First();
            var rotM = methods.FirstOrDefault(x => x.Closure.Has(LocalRotate))
                       ?? methods.FirstOrDefault(x => m.ClosureMethods(x).Any(y => rotationClasses.Contains(y.Owner) && y.Owner.Outer != outer && TakesAngles(y)));
            if (rotM is null) continue;
            var viaManager = !rotM.Closure.Has(LocalRotate)
                ? m.ClosureMethods(rotM).FirstOrDefault(y => rotationClasses.Contains(y.Owner) && TakesAngles(y)) : null;
            var fr = new Finding
            {
                Severity = Severity.Critical, Category = "Бой", Analyzer = Name, Weight = 27 + NameBonus(outer, "aim"), Signal = "AimAssist",
                Location = aimM.Owner.Name,
                Title = $"AimAssist — модуль выбирает цель, считает угол на неё и поворачивает игрока ({Short(outer)})",
                Why = "В одном модуле: выбор цели (перебор сущностей мира / сущность под прицелом), расчёт угла до сущности (atan2 / wrapDegrees) и поворот локального игрока — напрямую или через общий «менеджер поворотов» чита. Прицел наводится программой — это AimAssist/Aimbot.",
            }
            .Ev("Выбор цели", Ev.Where(m, selM))
            .Ev("Расчёт угла на сущность", Ev.Where(m, aimM) + string.Concat(AimMethods(m, aimM).Where(x => x != aimM).Take(2).Select(x => $"\n→ {m.Label(x)} (класс {x.Owner.Name.Replace('/', '.')})")))
            .Ev("Поворот", Ev.Where(m, rotM) + (viaManager is not null ? $"\nчерез менеджер поворотов: {m.Label(viaManager)} (класс {viaManager.Owner.Name.Replace('/', '.')})" : ""))
            .EvLines("Обращения", Ev.Atoms(m, selM, EntityList, CrosshairEntity, LivingTarget, TargetCheck, Distance)
                .Concat(Ev.Atoms(m, aimM, AimMath, TargetPos))
                .Concat(Ev.Atoms(m, viaManager ?? rotM, LocalRotate)));
            ctx.Add(fr);
        }

        foreach (var (unit, hit) in aim)
        {
            var mn = hit.M;
            bool silent = m.ClosureMethods(mn).Any(x => x.Hits.TryGetValue(Rotate, out var rl) && rl.Any(r => r.Contains("MovePlayerPacket") || r.Contains("MoveC2SPacket")));
            ctx.Add(new Finding
            {
                Severity = Severity.Critical, Category = "Бой", Analyzer = Name, Weight = 28 + NameBonus(unit, "aim"), Signal = "AimAssist",
                Location = mn.Owner.Name,
                Title = $"AimAssist — автоматический доворот прицела на цель ({Short(unit)}){(silent ? ", в т.ч. «тихие» повороты пакетом" : "")}",
                Why = "Код выбирает цель (перебирает сущности мира или берёт ту, что под прицелом), считает угол до её координат (atan2 / wrapDegrees) и сам поворачивает игрока (setYRot/setXRot, turn или пакет поворота). Прицел наводится программой — это AimAssist/Aimbot.",
            }
            .Ev("Где", Ev.Where(m, mn))
            .EvLines("Цель, угол и поворот", Ev.Atoms(m, mn, EntityList, CrosshairEntity, Raycast, LivingTarget, TargetCheck, Distance, TargetPos, AimMath, LocalRotate, KeyPress))
            .EvLines("Расчёт угла на сущность", AimMethods(m, mn).Take(4).Select(x => m.Label(x))));
        }

        foreach (var (unit, hit) in reach)
        {
            var mn = hit.M;
            ctx.Add(new Finding
            {
                Severity = Severity.Critical, Category = "Бой", Analyzer = Name, Weight = 28, Signal = "Reach",
                Location = mn.Owner.Name,
                Title = $"Reach — изменение атрибута дальности удара ({Short(unit)})",
                Why = "Код меняет атрибут игрока ENTITY_INTERACTION_RANGE (setBaseValue / модификатор) — дальность, на которой можно ударить сущность. Ванильное значение 3 блока, всё больше — Reach.",
            }
            .Ev("Где", Ev.Where(m, mn))
            .EvLines("Обращения", Ev.Atoms(m, mn, RangeAttr, AttrSet, KeyPress)));
        }

        foreach (var (unit, hit) in hitbox)
        {
            var mn = hit.M;
            bool others = mn.Closure.Has(EntityList);
            ctx.Add(new Finding
            {
                Severity = others ? Severity.Critical : Severity.High, Category = "Бой", Analyzer = Name, Weight = others ? 30 : 14, Signal = "HitBox",
                Location = mn.Owner.Name,
                Title = $"HitBox — код подменяет хитбоксы сущностей ({Short(unit)})",
                Why = others
                    ? "Код перебирает сущности мира и каждой выставляет новую, увеличенную область попадания (Entity.setBoundingBox с построенным/расширенным AABB). По такой цели проще попасть — это HitBox."
                    : "Код выставляет сущности новую область попадания (Entity.setBoundingBox с построенным/расширенным AABB). Если это чужие сущности — это HitBox.",
            }
            .Ev("Где", Ev.Where(m, mn))
            .EvLines("Обращения", Ev.Atoms(m, mn, EntityList, GetBox, BoxGrow, SetBox, KeyPress)));
        }

        foreach (var (unit, hit) in hitboxAim)
        {
            if (hitbox.ContainsKey(unit)) continue;
            var mn = hit.M;
            ctx.Add(new Finding
            {
                Severity = Severity.High, Category = "Бой", Analyzer = Name, Weight = 14, Signal = "HitBox",
                Location = mn.Owner.Name,
                Title = $"HitBox — прицеливание по расширенной области попадания ({Short(unit)})",
                Why = "Код берёт хитбокс цели, расширяет его (AABB.inflate) и трассирует по нему луч прицела, после чего атакует. Это собственная реализация увеличенных хитбоксов.",
            }
            .Ev("Где", Ev.Where(m, mn))
            .EvLines("Обращения", Ev.Atoms(m, mn, GetBox, BoxGrow, Raycast, Crosshair, Attack)));
        }
    }

    /// <summary>
    /// Угол считается именно на сущность: метод с atan2/wrapDegrees принимает сущность параметром или сам выбирает её
    /// (перебор мира / сущность под прицелом). Доворот на блок (спавнер, сундук, клетка) — не AimAssist.
    /// </summary>
    private static bool AimsAtEntity(ModModel m, MethodNode root) => AimMethods(m, root).Any();

    private static IEnumerable<MethodNode> AimMethods(ModModel m, MethodNode root) =>
        m.ClosureMethods(root).Where(x => x.Direct.Has(AimMath) && (x.Direct.Any(EntityList, CrosshairEntity) || EntityParam(m, x)));

    /// <summary>Метод принимает углы: два float/double подряд (yaw, pitch) или объект поворота своего класса.</summary>
    private static bool TakesAngles(MethodNode y)
    {
        string d = y.Mi.Desc;
        return d.Contains("FF") && d.IndexOf("FF") < d.IndexOf(')') || d.Contains("DD") && d.IndexOf("DD") < d.IndexOf(')');
    }

    private static bool EntityParam(ModModel m, MethodNode x)
    {
        string d = x.Mi.Desc;
        int close = d.IndexOf(')');
        if (close < 0) return false;
        foreach (var cls in Descriptors.ClassesIn(d[..close]))
        {
            if (!GameNames.IsGame(cls)) continue;
            foreach (var k in m.Names.ClassKeys(cls))
                if (k is "C:LivingEntity" or "C:Player" or "C:Entity") return !(m.Names.ShortClass(cls) is "LocalPlayer" or "ClientPlayerEntity");
        }
        return false;
    }

    /// <summary>Удар наносит код: атака, программный клик атаки, нажатие клавиши атаки или эмуляция мыши.</summary>
    private static bool AttacksInCode(AtomSet s) =>
        s.Has(Attack) || s.Has(StartAttack) || (s.Has(KeyAttack) && s.Has(KeyPress)) || s.Has(MouseEmu);

    private static int Score(MethodNode mn, params int[] atoms)
    {
        int sc = 0;
        foreach (var a in atoms) { if (mn.Direct.Has(a)) sc += 3; else if (mn.Closure.Has(a)) sc += 1; }
        return sc;
    }

    private static void Keep(Dictionary<string, Hit> d, string unit, MethodNode mn, int score)
    {
        if (!d.TryGetValue(unit, out var h) || score > h.Score) d[unit] = new Hit { M = mn, Score = score };
    }

    private static void Reach(MethodNode root, HashSet<MethodNode> set)
    {
        var q = new Queue<(MethodNode, int)>();
        q.Enqueue((root, 0));
        while (q.Count > 0)
        {
            var (m, d) = q.Dequeue();
            if (!set.Add(m) || d >= ModModel.ClosureDepth) continue;
            foreach (var c in m.Callees) q.Enqueue((c, d + 1));
        }
    }

    private static string Short(string unit) => unit[(unit.LastIndexOf('/') + 1)..];

    /// <summary>Модуль, названный по функции (TriggerbotModule, KillAura), — самый наглядный пример: показываем первым.</summary>
    private static double NameBonus(string unit, string word) => Short(unit).Contains(word, StringComparison.OrdinalIgnoreCase) ? 5 : 0;
}
