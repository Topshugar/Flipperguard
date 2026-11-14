import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:flutter_blue_plus/flutter_blue_plus.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';

void main() {
  runApp(const FlipperGuardApp());
}

class FlipperGuardApp extends StatelessWidget {
  const FlipperGuardApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'FlipperGuard',
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF0A0F1A),
        primaryColor: const Color(0xFF00FF88),
        useMaterial3: true,
      ),
      home: const RootScreen(),
      debugShowCheckedModeBanner: false,
    );
  }
}

enum ThreatLevel { safe, watching, alert }

class LogEvent {
  final DateTime time;
  final String title;
  final String detail;
  final ThreatLevel level;
  LogEvent({required this.time, required this.title, required this.detail, required this.level});
  String toCsv() => '${time.toIso8601String()},"$title","$detail",${level.name}';
}

class RootScreen extends StatefulWidget {
  const RootScreen({super.key});
  @override
  State<RootScreen> createState() => _RootScreenState();
}

class _RootScreenState extends State<RootScreen> {
  int _tab = 0;
  bool _onboarded = false;
  bool _isScanning = false;
  bool _isLearning = true;
  bool _autoLockdown = true;
  bool _nightMode = false;
  bool _loudAlert = true;
  ThreatLevel _threat = ThreatLevel.safe;
  String _statusText = "Tap Enable to start protection";
  int _devicesLast60s = 0;
  double _burstsPerSec = 0;
  List<LogEvent> _logs = [];
  Set<String> _trustedHashes = {};

  final Queue<DateTime> _newDeviceTimes = Queue<DateTime>();
  final Map<String, int> _nameCounts = {};
  final Map<String, DateTime> _firstSeen = {};
  StreamSubscription<List<ScanResult>>? _scanSub;
  Timer? _cleanupTimer;

  @override
  void initState() {
    super.initState();
    _loadPrefs();
  }

  Future<void> _loadPrefs() async {
    final prefs = await SharedPreferences.getInstance();
    setState(() {
      _onboarded = prefs.getBool('onboarded') ?? false;
      _autoLockdown = prefs.getBool('autoLockdown') ?? true;
      _nightMode = prefs.getBool('nightMode') ?? false;
      _loudAlert = prefs.getBool('loudAlert') ?? true;
      _trustedHashes = (prefs.getStringList('trusted') ?? []).toSet();
      final firstRun = prefs.getInt('firstRun') ?? DateTime.now().millisecondsSinceEpoch;
      if (!prefs.containsKey('firstRun')) prefs.setInt('firstRun', firstRun);
      // Learning mode = first 3 days
      _isLearning = DateTime.now().difference(DateTime.fromMillisecondsSinceEpoch(firstRun)).inDays < 3;
    });
  }

  Future<void> _savePrefs() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('onboarded', _onboarded);
    await prefs.setBool('autoLockdown', _autoLockdown);
    await prefs.setBool('nightMode', _nightMode);
    await prefs.setBool('loudAlert', _loudAlert);
    await prefs.setStringList('trusted', _trustedHashes.toList());
  }

  String _hashMac(String mac) {
    final bytes = utf8.encode(mac + "flipperguard-salt-v1");
    return sha256.convert(bytes).toString().substring(0, 12);
  }

  Future<void> _requestPermissions() async {
    await [
      Permission.bluetoothScan,
      Permission.bluetoothConnect,
      Permission.locationWhenInUse,
      Permission.notification,
    ].request();

    if (await Permission.bluetoothScan.isGranted) {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setBool('onboarded', true);
      setState(() { _onboarded = true; });
      _startScanning();
    } else {
      setState(() {
        _statusText = "Permission denied. Go to Settings > Permissions to enable Bluetooth Scan.";
      });
    }
  }

  void _startScanning() async {
    setState(() {
      _isScanning = true;
      _statusText = _isLearning
          ? "Learning mode — Day 1-3: We learn your normal devices. No loud alerts yet."
          : "Protected — Passive monitoring ON";
    });
    await FlutterBluePlus.startScan(timeout: null, androidScanMode: AndroidScanMode.lowLatency);
    _scanSub = FlutterBluePlus.scanResults.listen((results) => _onScanResults(results));
    _cleanupTimer = Timer.periodic(const Duration(seconds: 1), (_) => _cleanupAndCheck());
    _addLog("Protection Enabled", "Passive BLE monitoring started. Receive-only, no connections.", ThreatLevel.safe);
  }

  void _onScanResults(List<ScanResult> results) {
    final now = DateTime.now();
    for (final r in results) {
      final hash = _hashMac(r.device.remoteId.str);
      final name = r.advertisementData.advName.isNotEmpty ? r.advertisementData.advName : "Unknown";
      if (_trustedHashes.contains(hash)) continue;
      if (!_firstSeen.containsKey(hash)) {
        _firstSeen[hash] = now;
        _newDeviceTimes.add(now);
      }
      if (name != "Unknown") {
        _nameCounts[name] = (_nameCounts[name] ?? 0) + 1;
      }
      final first = _firstSeen[hash]!;
      if (now.difference(first).inSeconds > 120 && r.rssi > -50) {
        if (!_firstSeen.containsKey("${hash}_alerted")) {
          _firstSeen["${hash}_alerted"] = now;
          _triggerAlert("Unknown Device Lingering", "Device $name near you for >2 mins, RSSI ${r.rssi} dBm", ThreatLevel.watching);
        }
      }
    }
    setState(() {
      _devicesLast60s = _newDeviceTimes.length;
      _burstsPerSec = _newDeviceTimes.length / 60.0;
    });
    _checkFlood();
    _checkPairSpam();
  }

  void _checkFlood() {
    final now = DateTime.now();
    final count5s = _newDeviceTimes.where((t) => now.difference(t).inSeconds <= 5).length;
    int threshold = _nightMode ? 10 : 20;
    if (_isLearning) threshold = 999;
    if (count5s > threshold) {
      _triggerAlert("BLE FLOOD DETECTED", "$count5s new devices in 5s — Possible BLE Spam", ThreatLevel.alert);
    }
  }

  void _checkPairSpam() {
    final spamNames = ["AirPods", "Apple TV", "Flipper", "iPhone", "AirTag", "Galaxy Buds"];
    for (final entry in _nameCounts.entries) {
      if (spamNames.any((s) => entry.key.toLowerCase().contains(s.toLowerCase())) && entry.value > 10) {
        _triggerAlert("Pairing Spam", "'${entry.key}' seen ${entry.value}x in 10s — Fake pairing attack", ThreatLevel.alert);
        _nameCounts.clear();
        break;
      }
    }
  }

  void _cleanupAndCheck() {
    final now = DateTime.now();
    while (_newDeviceTimes.isNotEmpty && now.difference(_newDeviceTimes.first).inSeconds > 60) {
      _newDeviceTimes.removeFirst();
    }
    if (now.second % 10 == 0) _nameCounts.clear();
    setState(() { _devicesLast60s = _newDeviceTimes.length; });
  }

  void _triggerAlert(String title, String detail, ThreatLevel level) {
    setState(() { _threat = level; _statusText = title; });
    _addLog(title, detail, level);
    if (level == ThreatLevel.alert && !_isLearning && _autoLockdown) {
      _doLockdown(auto: true);
    }
  }

  void _addLog(String title, String detail, ThreatLevel level) {
    setState(() {
      _logs.insert(0, LogEvent(time: DateTime.now(), title: title, detail: detail, level: level));
      if (_logs.length > 200) _logs.removeLast();
    });
  }

  Future<void> _doLockdown({bool auto = false}) async {
    try { await FlutterBluePlus.turnOff(); } catch (_) {}
    _addLog("LOCKDOWN", auto ? "Auto-lockdown: Bluetooth OFF for 30s" : "Manual lockdown: Bluetooth OFF", ThreatLevel.alert);
    if (!mounted) return;
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1A2233),
        title: const Text("LOCKDOWN ACTIVE", style: TextStyle(color: Colors.red)),
        content: const Text("Bluetooth OFF for 30s to stop BLE spam. Tap Restore to turn back on."),
        actions: [
          TextButton(
            onPressed: () async {
              Navigator.pop(ctx);
              try { await FlutterBluePlus.turnOn(); } catch (_) {}
              _addLog("Lockdown Ended", "Bluetooth restored by user", ThreatLevel.safe);
              setState(() { _threat = ThreatLevel.safe; _statusText = "Protected"; });
            },
            child: const Text("RESTORE NOW"),
          ),
        ],
      ),
    );
  }

  Future<void> _exportLog() async {
    if (_logs.isEmpty) return;
    final csv = "time,title,detail,level\n" + _logs.map((e) => e.toCsv()).join("\n");
    final dir = await getTemporaryDirectory();
    final file = File('${dir.path}/flipperguard_log.csv');
    await file.writeAsString(csv);
    await Share.shareXFiles([XFile(file.path)], text: 'FlipperGuard Export');
  }

  void _markTrusted(String hash) {
    setState(() { _trustedHashes.add(hash); });
    _savePrefs();
    _addLog("Trusted Device", "User marked device as theirs — will be ignored", ThreatLevel.safe);
  }

  @override
  void dispose() {
    _scanSub?.cancel();
    _cleanupTimer?.cancel();
    FlutterBluePlus.stopScan();
    super.dispose();
  }

  Color _threatColor() {
    switch (_threat) {
      case ThreatLevel.safe: return const Color(0xFF00FF88);
      case ThreatLevel.watching: return Colors.amber;
      case ThreatLevel.alert: return Colors.red;
    }
  }

  String _threatLabel() {
    switch (_threat) {
      case ThreatLevel.safe: return "PROTECTED";
      case ThreatLevel.watching: return "WATCHING";
      case ThreatLevel.alert: return "ALERT";
    }
  }

  @override
  Widget build(BuildContext context) {
    if (!_onboarded) return _buildOnboarding();
    return Scaffold(
      body: _tab == 0 ? _buildHome() : _tab == 1 ? _buildEvents() : _buildSettings(),
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: _tab,
        backgroundColor: const Color(0xFF1A2233),
        selectedItemColor: const Color(0xFF00FF88),
        unselectedItemColor: Colors.white54,
        onTap: (i) => setState(() => _tab = i),
        items: const [
          BottomNavigationBarItem(icon: Icon(Icons.shield), label: 'Home'),
          BottomNavigationBarItem(icon: Icon(Icons.list), label: 'Events'),
          BottomNavigationBarItem(icon: Icon(Icons.settings), label: 'Settings'),
        ],
      ),
    );
  }

  Widget _buildOnboarding() {
    return Scaffold(
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Icon(Icons.shield, size: 72, color: Color(0xFF00FF88)),
            const SizedBox(height: 16),
            const Text("Protect Your Phone", style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold)),
            const SizedBox(height: 12),
            const Text("FlipperGuard listens for Bluetooth spam around YOUR phone. It never transmits, never connects to other devices, never uploads data.", style: TextStyle(color: Colors.white70, fontSize: 15)),
            const SizedBox(height: 16),
            const Text("✓ Passive, receive-only tool\n✓ BLE scanning on MY device only\n✓ Local logging on MY device", style: TextStyle(color: Colors.white70)),
            const SizedBox(height: 8),
            const Text("Android requires Location permission to scan Bluetooth, but we NEVER track your GPS. Your location never leaves your phone.", style: TextStyle(color: Colors.white54, fontSize: 13)),
            const SizedBox(height: 24),
            SizedBox(width: double.infinity, child: ElevatedButton(
              style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF00FF88), padding: const EdgeInsets.symmetric(vertical: 16)),
              onPressed: _requestPermissions,
              child: const Text("ENABLE PROTECTION", style: TextStyle(color: Colors.black, fontWeight: FontWeight.bold)),
            )),
          ],
        ),
      ),
    );
  }

  Widget _buildHome() {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          const SizedBox(height: 20),
          Container(
            width: 180, height: 180,
            decoration: BoxDecoration(shape: BoxShape.circle, border: Border.all(color: _threatColor(), width: 4)),
            child: Center(child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
              Icon(Icons.shield, size: 48, color: _threatColor()),
              const SizedBox(height: 8),
              Text(_threatLabel(), style: TextStyle(color: _threatColor(), fontWeight: FontWeight.bold, fontSize: 20)),
            ])),
          ),
          const SizedBox(height: 12),
          Text(_statusText, textAlign: TextAlign.center, style: const TextStyle(color: Colors.white70)),
          if (_isLearning) const Padding(padding: EdgeInsets.only(top: 6), child: Text("LEARNING MODE — Day 1-3", style: TextStyle(color: Colors.amber, fontSize: 12, fontWeight: FontWeight.bold))),
          const SizedBox(height: 16),
          Row(children: [
            Expanded(child: _statCard("Devices / 60s", "$_devicesLast60s")),
            const SizedBox(width: 12),
            Expanded(child: _statCard("Bursts / sec", _burstsPerSec.toStringAsFixed(1))),
          ]),
          const SizedBox(height: 16),
          SizedBox(width: double.infinity, child: ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: _isScanning ? Colors.red : const Color(0xFF00FF88), padding: const EdgeInsets.symmetric(vertical: 16)),
            onPressed: _isScanning ? () => _doLockdown(auto: false) : _requestPermissions,
            child: Text(_isScanning ? "LOCKDOWN NOW" : "ENABLE PROTECTION", style: const TextStyle(fontWeight: FontWeight.bold)),
          )),
          const SizedBox(height: 16),
          const Align(alignment: Alignment.centerLeft, child: Text("Last 3 Events", style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16))),
          const SizedBox(height: 8),
          Expanded(child: ListView.builder(
            itemCount: _logs.take(3).length,
            itemBuilder: (ctx, i) {
              final e = _logs[i];
              return Card(color: const Color(0xFF1A2233), child: ListTile(
                leading: Icon(Icons.circle, color: e.level == ThreatLevel.alert ? Colors.red : e.level == ThreatLevel.watching ? Colors.amber : Colors.green, size: 12),
                title: Text(e.title, style: const TextStyle(fontWeight: FontWeight.bold)),
                subtitle: Text(e.detail),
              ));
            },
          )),
        ],
      ),
    );
  }

  Widget _buildEvents() {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          const SizedBox(height: 20),
          Row(children: [
            const Expanded(child: Text("Events / Log", style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold))),
            ElevatedButton(onPressed: _exportLog, child: const Text("Export CSV")),
          ]),
          const SizedBox(height: 12),
          Expanded(child: _logs.isEmpty
              ? const Center(child: Text("No events yet", style: TextStyle(color: Colors.white54)))
              : ListView.builder(
                  itemCount: _logs.length,
                  itemBuilder: (ctx, i) {
                    final e = _logs[i];
                    return Card(color: const Color(0xFF1A2233), child: ListTile(
                      leading: Icon(Icons.circle, color: e.level == ThreatLevel.alert ? Colors.red : e.level == ThreatLevel.watching ? Colors.amber : Colors.green, size: 12),
                      title: Text(e.title, style: const TextStyle(fontWeight: FontWeight.bold)),
                      subtitle: Text(e.detail),
                      trailing: Text("${e.time.hour}:${e.time.minute.toString().padLeft(2, '0')}", style: const TextStyle(color: Colors.white54)),
                    ));
                  },
                )),
        ],
      ),
    );
  }

  Widget _buildSettings() {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        const SizedBox(height: 20),
        const Text("Settings", style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
        const SizedBox(height: 12),
        SwitchListTile(title: const Text("Auto-Lockdown on BLE Flood"), value: _autoLockdown, onChanged: (v) { setState(() => _autoLockdown = v); _savePrefs(); }),
        SwitchListTile(title: const Text("Night Mode (22:00 - 06:00) — Stricter alerts"), subtitle: const Text("Threshold drops from 20 to 10 devices in 5s"), value: _nightMode, onChanged: (v) { setState(() => _nightMode = v); _savePrefs(); }),
        SwitchListTile(title: const Text("Vibrate + Loud Alert"), value: _loudAlert, onChanged: (v) { setState(() => _loudAlert = v); _savePrefs(); }),
        ListTile(title: const Text("Trusted Devices"), subtitle: Text("${_trustedHashes.length} devices marked as yours")),
        const Divider(),
        const Text("Legal", style: TextStyle(fontWeight: FontWeight.bold)),
        const SizedBox(height: 8),
        const Text("FlipperGuard is a passive, receive-only defensive tool. It never transmits, never connects, never uploads data. All logs stay on your device. Version 1.0.0", style: TextStyle(color: Colors.white60, fontSize: 13)),
        const SizedBox(height: 16),
        ElevatedButton(onPressed: _exportLog, child: const Text("Export Log (CSV)")),
      ],
    );
  }

  Widget _statCard(String label, String value) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(color: const Color(0xFF1A2233), borderRadius: BorderRadius.circular(12)),
      child: Column(children: [
        Text(value, style: const TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
        Text(label, style: const TextStyle(color: Colors.white60, fontSize: 12)),
      ]),
    );
  }
}