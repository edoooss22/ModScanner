using System.Text.RegularExpressions;

namespace ModScanner.Analysis;

/// <summary>
/// Словарь «атомов» — именованных наборов обращений к API. Атом срабатывает, если метод обращается
/// хотя бы к одному ключу набора. Ключи:
///   «Класс.член»        — член игры (имена Mojang и Yarn, простое имя класса; «=» в конце — запись в поле);
///   «C:Класс»           — ссылка на класс игры (включая предков);
///   «J:пакет/Класс.член» и «JC:пакет/Класс» — JDK и сторонние библиотеки.
/// Правила анализаторов — сочетания атомов в одном методе (с учётом вызываемых им методов мода).
/// </summary>
internal static class Vocab
{
    public sealed class Atom
    {
        public int Id;
        public string Name = "";
        public string Title = "";
        public string[] Keys = Array.Empty<string>();
    }

    public static readonly List<Atom> All = new();
    private static readonly Dictionary<string, List<int>> _byKey = new(StringComparer.Ordinal);

    private static int A(string name, string title, params string[] keys)
    {
        var a = new Atom { Id = All.Count, Name = name, Title = title, Keys = keys };
        All.Add(a);
        foreach (var k in keys)
        {
            if (!_byKey.TryGetValue(k, out var l)) _byKey[k] = l = new List<int>();
            l.Add(a.Id);
        }
        return a.Id;
    }

    public static IReadOnlyList<int> AtomsOf(string key) => _byKey.TryGetValue(key, out var l) ? l : Array.Empty<int>();

    // ----------------------------------------------------------------- бой

    public static readonly int Crosshair = A("crosshair", "цель под прицелом",
        "Minecraft.hitResult", "Minecraft.crosshairPickEntity", "GameRenderer.pick", "EntityHitResult.getEntity",
        "MinecraftClient.crosshairTarget", "MinecraftClient.targetedEntity", "GameRenderer.updateCrosshairTarget", "GameRenderer.findCrosshairTarget");

    public static readonly int Raycast = A("raycast", "собственная трассировка луча по сущностям",
        "ProjectileUtil.getEntityHitResult", "ProjectileUtil.getHitResultOnViewVector", "AABB.clip",
        "ProjectileUtil.raycast", "ProjectileUtil.getEntityCollision", "Box.raycast");

    public static readonly int Attack = A("attack", "атака сущности",
        "MultiPlayerGameMode.attack", "MultiPlayerGameMode.piercingAttack", "ServerboundInteractPacket.createAttackPacket",
        "ClientPlayerInteractionManager.attackEntity", "ClientPlayerInteractionManager.attackWithPiercingWeapon", "PlayerInteractEntityC2SPacket.attack");

    public static readonly int StartAttack = A("startAttack", "программный клик атаки (Minecraft.startAttack)",
        "Minecraft.startAttack", "MinecraftClient.doAttack");

    public static readonly int KeyAttack = A("keyAttack", "клавиша атаки",
        "Options.keyAttack", "GameOptions.attackKey");

    public static readonly int KeyPress = A("keyPress", "нажатие клавиши кодом",
        "KeyMapping.click", "KeyMapping.set", "KeyMapping.setDown", "KeyMapping.clickCount=", "KeyMapping.isDown=",
        "KeyBinding.onKeyPressed", "KeyBinding.setKeyPressed", "KeyBinding.setPressed", "KeyBinding.timesPressed=", "KeyBinding.pressed=");

    public static readonly int MouseEmu = A("mouseEmu", "эмуляция нажатия мыши",
        "J:java/awt/Robot.mousePress", "J:java/awt/Robot.mouseRelease", "MouseHandler.onButton", "MouseHandler.onPress", "Mouse.onMouseButton");

    public static readonly int Swing = A("swing", "взмах рукой",
        "LivingEntity.swing", "C:ServerboundSwingPacket", "LivingEntity.swingHand", "C:HandSwingC2SPacket");

    public static readonly int EntityList = A("entityList", "перебор сущностей мира",
        "ClientLevel.entitiesForRendering", "ClientLevel.players", "Level.getEntities", "Level.getEntitiesOfClass", "Level.players",
        "EntityGetter.getEntities", "EntityGetter.getEntitiesOfClass", "EntityGetter.players", "EntityGetter.getNearestPlayer", "EntityGetter.getNearbyPlayers",
        "ClientWorld.getEntities", "ClientWorld.getPlayers", "World.getOtherEntities", "World.getEntitiesByClass", "World.getEntitiesByType",
        "World.getPlayers", "EntityView.getOtherEntities", "EntityView.getEntitiesByClass", "EntityView.getPlayers", "EntityView.getClosestPlayer");

    public static readonly int Distance = A("distance", "расчёт дистанции до цели",
        "Entity.distanceTo", "Entity.distanceToSqr", "Vec3.distanceTo", "Vec3.distanceToSqr", "Entity.closerThan",
        "Entity.squaredDistanceTo", "Vec3d.distanceTo", "Vec3d.squaredDistanceTo", "Entity.isInRange");

    public static readonly int Rotate = A("rotate", "запись угла обзора",
        "Entity.setYRot", "Entity.setXRot", "Entity.setYHeadRot", "Entity.yRot=", "Entity.xRot=", "LivingEntity.setYHeadRot",
        "Entity.setYaw", "Entity.setPitch", "Entity.setHeadYaw", "C:ServerboundMovePlayerPacket$Rot", "C:PlayerMoveC2SPacket$LookAndOnGround");

    public static readonly int Turn = A("turn", "поворот камеры игрока (как от мыши)",
        "Entity.turn", "Entity.changeLookDirection", "Entity.xRotO=", "Entity.yRotO=", "Entity.prevYaw=", "Entity.prevPitch=");

    public static readonly int AimMath = A("aimMath", "расчёт угла на цель (atan2 / wrapDegrees)",
        "J:java/lang/Math.atan2", "J:java/lang/StrictMath.atan2", "Mth.atan2", "MathHelper.atan2", "Mth.wrapDegrees", "MathHelper.wrapDegrees",
        "Mth.approachDegrees", "MathHelper.stepUnwrappedAngleTowards", "J:java/lang/Math.asin");

    public static readonly int TargetPos = A("targetPos", "координаты цели",
        "Entity.getX", "Entity.getY", "Entity.getZ", "Entity.position", "Entity.getEyePosition", "Entity.getEyeY", "AABB.getCenter",
        "Entity.getPos", "Entity.getEyePos", "Box.getCenter", "Entity.getBoundingBox");

    public static readonly int LivingTarget = A("livingTarget", "цель — игрок/живая сущность",
        "C=Player", "C=LivingEntity", "C=AbstractClientPlayer", "C=RemotePlayer", "C=PlayerEntity", "C=OtherClientPlayerEntity", "C=AbstractClientPlayerEntity",
        "ClientLevel.players", "EntityGetter.players", "EntityGetter.getNearestPlayer", "Level.players", "ClientWorld.getPlayers", "World.getPlayers",
        "EntityView.getPlayers", "EntityView.getClosestPlayer", "LivingEntity.getHealth", "Entity.isAlive", "LivingEntity.isDeadOrDying", "LivingEntity.isDead");

    public static readonly int CrosshairEntity = A("crosshairEntity", "сущность под прицелом",
        "Minecraft.crosshairPickEntity", "EntityHitResult.getEntity", "MinecraftClient.targetedEntity");

    public static readonly int LocalRotate = A("localRotate", "поворот локального игрока (или пакет поворота)",
        "LP:setYRot", "LP:setXRot", "LP:yRot=", "LP:xRot=", "LP:turn", "LP:setYHeadRot", "LP:setYaw", "LP:setPitch", "LP:changeLookDirection", "LP:setHeadYaw",
        "C:ServerboundMovePlayerPacket$Rot", "C:ServerboundMovePlayerPacket$PosRot", "C:PlayerMoveC2SPacket$LookAndOnGround", "C:PlayerMoveC2SPacket$Full");

    public static readonly int PlayerTarget = A("playerTarget", "цель — другой игрок",
        "C=Player", "C=AbstractClientPlayer", "C=RemotePlayer", "C=PlayerEntity", "C=OtherClientPlayerEntity", "C=AbstractClientPlayerEntity",
        "ClientLevel.players", "EntityGetter.players", "EntityGetter.getNearestPlayer", "EntityGetter.getNearbyPlayers", "Level.players",
        "ClientWorld.getPlayers", "World.getPlayers", "EntityView.getPlayers", "EntityView.getClosestPlayer", "Level.getNearestPlayer");

    public static readonly int MouseTurnHook = A("mouseTurn", "обработка поворота мыши", "MouseHandler.turnPlayer", "Mouse.updateMouse");

    public static readonly int TargetCheck = A("targetCheck", "отбор цели (жива/здоровье/кулдаун)",
        "Entity.isAlive", "LivingEntity.getHealth", "LivingEntity.isDeadOrDying", "Player.getAttackStrengthScale",
        "PlayerEntity.getAttackCooldownProgress", "LivingEntity.isDead");

    public static readonly int RangeRead = A("rangeRead", "дальность взаимодействия",
        "Player.entityInteractionRange", "Player.isWithinEntityInteractionRange", "Player.isWithinAttackRange",
        "PlayerEntity.getEntityInteractionRange", "PlayerEntity.canInteractWithEntity", "PlayerEntity.canAttackEntityIn");

    public static readonly int RangeAttr = A("rangeAttr", "атрибут дальности удара",
        "Attributes.ENTITY_INTERACTION_RANGE", "EntityAttributes.ENTITY_INTERACTION_RANGE", "EntityAttributes.PLAYER_ENTITY_INTERACTION_RANGE");

    public static readonly int AttrSet = A("attrSet", "изменение атрибута",
        "AttributeInstance.setBaseValue", "AttributeInstance.addTransientModifier", "AttributeInstance.addPermanentModifier",
        "AttributeInstance.addOrUpdateTransientModifier", "AttributeInstance.addOrReplacePermanentModifier",
        "EntityAttributeInstance.setBaseValue", "EntityAttributeInstance.addTemporaryModifier", "EntityAttributeInstance.addPersistentModifier",
        "EntityAttributeInstance.updateModifier", "EntityAttributeInstance.overwritePersistentModifier");

    public static readonly int BoxGrow = A("boxGrow", "построение/расширение AABB",
        "AABB.inflate", "AABB.expandTowards", "AABB.<init>", "Box.expand", "Box.stretch", "Box.<init>");

    public static readonly int SetBox = A("setBox", "подмена хитбокса сущности (setBoundingBox)",
        "Entity.setBoundingBox", "Entity.dimensions=");

    public static readonly int GetBox = A("getBox", "хитбокс сущности",
        "Entity.getBoundingBox", "Entity.getPickRadius", "Entity.getTargetingMargin");

    // ----------------------------------------------------------------- пакеты

    public static readonly int SendPacket = A("sendPacket", "отправка пакета",
        "Connection.send", "Connection.doSendPacket", "ClientCommonPacketListenerImpl.send",
        "ClientConnection.send", "ClientConnection.sendInternal", "ClientCommonNetworkHandler.sendPacket",
        "J:io/netty/channel/Channel.writeAndFlush", "J:io/netty/channel/ChannelOutboundInvoker.writeAndFlush",
        "J:io/netty/channel/ChannelHandlerContext.writeAndFlush", "J:io/netty/channel/ChannelHandlerContext.write");

    public static readonly int HandlePacket = A("handlePacket", "ручная обработка входящего пакета",
        "Packet.handle", "Connection.genericsFtw", "Connection.channelRead0", "Packet.apply", "ClientConnection.handlePacket", "ClientConnection.channelRead0",
        "J:io/netty/channel/ChannelHandlerContext.fireChannelRead");

    public static readonly int PacketType = A("packet", "работа с пакетами игры", "C:Packet");

    public static readonly int PacketGeneric = A("packetGeneric", "пакеты в общем виде (интерфейс Packet)", "C=Packet");

    public static readonly int GetUser = A("getUser", "текущая сессия игрока (Minecraft.getUser)",
        "Minecraft.getUser", "Minecraft.user", "MinecraftClient.getSession", "MinecraftClient.session");

    public static readonly int KeepAlive = A("keepAlive", "пакеты KeepAlive / Ping-Pong (замер пинга сервером)",
        "C:ServerboundKeepAlivePacket", "C:ClientboundKeepAlivePacket", "C:ServerboundPongPacket", "C:ClientboundPingPacket",
        "C:KeepAliveC2SPacket", "C:KeepAliveS2CPacket", "C:CommonPongC2SPacket", "C:CommonPingS2CPacket",
        "ClientCommonPacketListenerImpl.handleKeepAlive", "ClientCommonPacketListenerImpl.handlePing",
        "ClientCommonNetworkHandler.onKeepAlive", "ClientCommonNetworkHandler.onPing");

    public static readonly int MovePacket = A("movePacket", "пакеты движения", "C:ServerboundMovePlayerPacket", "C:PlayerMoveC2SPacket");

    public static readonly int Clock = A("clock", "замер времени",
        "J:java/lang/System.currentTimeMillis", "J:java/lang/System.nanoTime");

    public static readonly int Delay = A("delay", "отложенное выполнение / пауза",
        "J:java/lang/Thread.sleep", "J:java/util/concurrent/ScheduledExecutorService.schedule", "J:java/util/concurrent/Executors.newScheduledThreadPool",
        "J:java/util/concurrent/Executors.newSingleThreadScheduledExecutor", "J:java/util/Timer.schedule", "J:java/util/concurrent/TimeUnit.sleep",
        "J:io/netty/util/concurrent/EventExecutorGroup.schedule", "J:io/netty/channel/EventLoop.schedule", "J:io/netty/util/concurrent/AbstractEventExecutor.schedule",
        "J:java/util/concurrent/CompletableFuture.delayedExecutor");

    public static readonly int QueueAdd = A("queueAdd", "накопление в коллекции",
        "J:java/util/List.add", "J:java/util/Queue.add", "J:java/util/Queue.offer", "J:java/util/Deque.add", "J:java/util/Deque.addLast",
        "J:java/util/Deque.offer", "J:java/util/Deque.offerLast", "J:java/util/ArrayList.add", "J:java/util/LinkedList.add",
        "J:java/util/concurrent/ConcurrentLinkedQueue.add", "J:java/util/concurrent/ConcurrentLinkedQueue.offer",
        "J:java/util/concurrent/LinkedBlockingQueue.offer", "J:java/util/concurrent/LinkedBlockingQueue.add", "J:java/util/concurrent/LinkedBlockingQueue.put",
        "J:java/util/concurrent/BlockingQueue.put", "J:java/util/concurrent/BlockingQueue.offer",
        "J:java/util/concurrent/CopyOnWriteArrayList.add", "J:java/util/ArrayDeque.add", "J:java/util/ArrayDeque.offer", "J:java/util/ArrayDeque.addLast",
        "J:java/util/concurrent/ConcurrentLinkedDeque.add", "J:java/util/concurrent/ConcurrentLinkedDeque.offer", "J:java/util/concurrent/ConcurrentLinkedDeque.addLast");

    public static readonly int Cancel = A("cancel", "отмена (CallbackInfo.cancel)",
        "J:org/spongepowered/asm/mixin/injection/callback/CallbackInfo.cancel", "J:org/spongepowered/asm/mixin/injection/callback/CallbackInfoReturnable.cancel");

    public static readonly int AutoRead = A("autoRead", "остановка чтения канала (setAutoRead)", "J:io/netty/channel/ChannelConfig.setAutoRead");

    public static readonly int Pipeline = A("pipeline", "вставка обработчика в конвейер Netty",
        "J:io/netty/channel/ChannelPipeline.addBefore", "J:io/netty/channel/ChannelPipeline.addAfter", "J:io/netty/channel/ChannelPipeline.addFirst",
        "J:io/netty/channel/ChannelPipeline.addLast", "J:io/netty/channel/ChannelPipeline.replace");

    public static readonly int SetReturn = A("setReturn", "подмена возвращаемого значения",
        "J:org/spongepowered/asm/mixin/injection/callback/CallbackInfoReturnable.setReturnValue");

    // ----------------------------------------------------------------- внешние сервисы и код

    public static readonly int Http = A("http", "HTTP-запрос",
        "JC:java/net/HttpURLConnection", "JC:javax/net/ssl/HttpsURLConnection", "J:java/net/URL.openConnection", "J:java/net/URL.openStream",
        "JC:java/net/http/HttpClient", "JC:java/net/http/HttpRequest", "JC:okhttp3/OkHttpClient", "JC:okhttp3/Request$Builder",
        "JC:org/apache/http/client/HttpClient", "JC:org/apache/http/impl/client/HttpClients", "JC:org/apache/hc/client5/http/impl/classic/HttpClients",
        "JC:kong/unirest/Unirest");

    public static readonly int Socket = A("socket", "сокет / WebSocket",
        "JC:java/net/Socket", "JC:javax/net/ssl/SSLSocket", "JC:javax/net/ssl/SSLSocketFactory", "JC:java/nio/channels/SocketChannel",
        "JC:java/net/DatagramSocket", "JC:java/net/http/WebSocket", "JC:java/net/http/WebSocket$Builder", "JC:com/neovisionaries/ws/client/WebSocketFactory",
        "JC:org/java_websocket/client/WebSocketClient", "JC:okhttp3/WebSocket");

    public static readonly int ReadNet = A("readNet", "чтение ответа из сети",
        "J:java/net/URLConnection.getInputStream", "J:java/net/HttpURLConnection.getInputStream", "J:javax/net/ssl/HttpsURLConnection.getInputStream",
        "J:java/net/URL.openStream", "J:java/net/Socket.getInputStream", "J:java/net/http/HttpClient.send", "J:java/net/http/HttpClient.sendAsync",
        "J:okhttp3/Call.execute", "J:okhttp3/ResponseBody.bytes", "J:okhttp3/ResponseBody.string", "J:java/net/URL.getContent");

    public static readonly int HwidApi = A("hwidApi", "сбор идентификаторов железа (HWID)",
        "J:java/net/NetworkInterface.getHardwareAddress", "J:oshi/hardware/ComputerSystem.getSerialNumber", "J:oshi/hardware/ComputerSystem.getHardwareUUID",
        "J:oshi/hardware/Baseboard.getSerialNumber", "J:oshi/hardware/CentralProcessor$ProcessorIdentifier.getProcessorID", "J:oshi/hardware/HWDiskStore.getSerial",
        "J:oshi/hardware/NetworkIF.getMacaddr", "J:java/lang/System.getenv");

    public static readonly int Process = A("process", "запуск процесса ОС",
        "JC:java/lang/ProcessBuilder", "J:java/lang/Runtime.exec");

    public static readonly int Crypto = A("crypto", "криптография / хеширование",
        "J:java/security/MessageDigest.getInstance", "JC:javax/crypto/Cipher", "JC:javax/crypto/spec/SecretKeySpec", "JC:java/security/Signature",
        "JC:java/security/KeyFactory", "JC:javax/crypto/KeyAgreement", "JC:java/security/KeyPairGenerator", "JC:javax/crypto/Mac");

    public static readonly int Exit = A("exit", "принудительное завершение игры",
        "J:java/lang/System.exit", "J:java/lang/Runtime.halt", "J:java/lang/Runtime.exit");

    public static readonly int DefineClass = A("defineClass", "определение класса из байтов",
        "J:*.defineClass", "J:java/lang/invoke/MethodHandles$Lookup.defineClass", "J:java/lang/invoke/MethodHandles$Lookup.defineHiddenClass");

    public static readonly int ClassLoader = A("classLoader", "собственный загрузчик классов",
        "JC:java/net/URLClassLoader", "JC:java/security/SecureClassLoader", "JC:sun/misc/Unsafe", "JC:jdk/internal/misc/Unsafe");

    public static readonly int FileWrite = A("fileWrite", "запись файла",
        "J:java/nio/file/Files.write", "J:java/nio/file/Files.copy", "J:java/io/FileOutputStream.<init>", "J:java/nio/file/Files.newOutputStream",
        "J:java/nio/file/Files.writeString");

    public static readonly int NativeLoad = A("nativeLoad", "загрузка нативной библиотеки",
        "J:java/lang/System.load", "J:java/lang/System.loadLibrary", "J:java/lang/Runtime.load", "J:java/lang/Runtime.loadLibrary");

    public static readonly int Browse = A("browse", "открытие браузера", "J:java/awt/Desktop.browse");

    public static readonly int Base64 = A("base64", "декодирование Base64", "J:java/util/Base64$Decoder.decode");

    public static readonly int SessionToken = A("sessionToken", "токен сессии Minecraft",
        "User.getAccessToken", "User.getSessionId", "User.accessToken", "Session.getAccessToken", "Session.getSessionId", "Session.accessToken");

    public static readonly int Instrument = A("instrument", "Java-агент / Attach API",
        "JC:java/lang/instrument/Instrumentation", "JC:com/sun/tools/attach/VirtualMachine");

    // ----------------------------------------------------------------- строки

    public sealed class StrAtom
    {
        public int Id;
        public Regex Rx = null!;
    }

    public static readonly int StrUrl = A("strUrl", "адрес в строках (URL)");
    public static readonly int StrHwid = A("strHwid", "строки HWID / идентификации железа");
    public static readonly int StrAuthStrong = A("strAuth", "строки лицензии / авторизации");
    public static readonly int StrWebhook = A("strWebhook", "Discord-вебхук");
    public static readonly int StrExe = A("strExe", "исполняемый файл в строках");
    public static readonly int StrStealer = A("strStealer", "пути к данным Telegram/Discord/браузеров/кошельков");

    public static readonly List<StrAtom> Strings = new()
    {
        new() { Id = StrUrl, Rx = new Regex(@"^(https?|wss?)://", RegexOptions.IgnoreCase | RegexOptions.Compiled) },
        new() { Id = StrUrl, Rx = new Regex(@"(https?|wss?)://[a-z0-9.\-]+", RegexOptions.IgnoreCase | RegexOptions.Compiled) },
        new() { Id = StrHwid, Rx = new Regex(@"\b(hwid|machineguid|csproduct|baseboard|diskdrive|volumeserial|processor_identifier|computername|hardware[ _-]?id|wmic)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled) },
        new() { Id = StrAuthStrong, Rx = new Regex(@"(licen[cs]e(?!s? ?(-|—)?(mit|apache|gpl|lgpl|bsd|mpl|cc0|unlicense))|\bhwid\b|subscription|activation|\bactivate\b|invalid key|key expired|\bauth(orization)? (failed|error|success)|\bdevice[_ ]?auth|лиценз|подписк|активац|авторизац|аутентиф)", RegexOptions.IgnoreCase | RegexOptions.Compiled) },
        new() { Id = StrWebhook, Rx = new Regex(@"discord(app)?\.com/api/webhooks/\d{6,}/[\w-]{20,}", RegexOptions.IgnoreCase | RegexOptions.Compiled) },
        new() { Id = StrStealer, Rx = new Regex(@"(^tdata$|[\\/]tdata\b|key_datas|D877F783D5D3EF8C|Local Storage[\\/]leveldb|\bLogin Data\b|\bLocal State\b|\bWeb Data\b|cookies\.sqlite|logins\.json|discordcanary|discordptb|\bExodus[\\/]|\bElectrum[\\/]|metamask|nkbihfbeogaeaoehlefnkodbefgpgknn|launcher_accounts(_microsoft_store)?\.json|essential[\\/]microsoft_accounts)", RegexOptions.IgnoreCase | RegexOptions.Compiled) },
        new() { Id = StrExe, Rx = new Regex(@"\.(exe|bat|cmd|ps1|vbs|scr|msi)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled) },
    };

    public static string Title(int id) => All[id].Title;
}

/// <summary>Множество атомов (битовая маска на 128 атомов).</summary>
internal struct AtomSet
{
    private ulong _a, _b;
    public void Add(int id) { if (id < 64) _a |= 1UL << id; else _b |= 1UL << (id - 64); }
    public readonly bool Has(int id) => id < 64 ? (_a & (1UL << id)) != 0 : (_b & (1UL << (id - 64))) != 0;
    public void Or(in AtomSet o) { _a |= o._a; _b |= o._b; }
    public readonly bool IsEmpty => _a == 0 && _b == 0;
    public readonly bool Any(params int[] ids) { foreach (var i in ids) if (Has(i)) return true; return false; }
    public readonly bool AllOf(params int[] ids) { foreach (var i in ids) if (!Has(i)) return false; return true; }
    public readonly IEnumerable<int> Ids() { for (int i = 0; i < 128; i++) if (Has(i)) yield return i; }
}
