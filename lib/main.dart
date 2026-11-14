import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:flutter_blue_plus/flutter_blue_plus.dart';
import 'package:permission_handler/permission_handler.dart';

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
      ),
      home: const HomeScreen(),
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
}

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  bool isScanning = false;
  bool isLearning = true;
  ThreatLevel threat = ThreatLevel.safe;
  String statusText = "Tap Enable to start protection";
  int devicesLast60s = 0;
  double burstsPerSec = 0;
  List<LogEvent> logs = [];
  final Set<String> trustedHashes = {};

  final Queue<DateTime> _newDeviceTimes = Queue<DateTime>();
  final Map<String, int> _nameCounts = {};
  final Map<String, DateTime> _firstSeen = {};
  StreamSubscription<List<ScanResult>>? _scanSub;
  Timer? _cleanupTimer;

  static const int FLOOD_THRESHOLD_5S = 20;
  static const int PAIR_SPAM_THRESHOLD = 10;
  static const int LINGER_SECONDS = 120;
  static const int LINGER_RSSI = -50;

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
      _startScanning();
    } else {
      setState(() {
        statusText = "Permission denied. Go to Settings > Permissions to enable Bluetooth Scan.";
      });
    }
  }

  void _startScanning() async {
    setState(() {
      isScanning = true;
      statusText = "Learning mode — Day 1-3: We learn your normal devices. No loud alerts yet.";
    });

    await FlutterBluePlus.startScan(
      timeout: null,
      androidScanMode: AndroidScanMode.lowLatency,
    );

    _scanSub = FlutterBluePlus.scanResults.listen((results) {
      _onScanResults(results);
    });

    _cleanupTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      _cleanupAndCheck();
    });

    _addLog("Protection Enabled", "Passive BLE monitoring started. Receive-only.", ThreatLevel.safe);
  }

  void _onScanResults(List<ScanResult> results) {
    final now = DateTime.now();

    for (final r in results) {
      final hash = _hashMac(r.device.remoteId.str);
      final name = r.advertisementData.advName.isNotEmpty
          ? r.advertisementData.advName
          : "Unknown";

      if (trustedHashes.contains(hash)) continue;

      if (!_firstSeen.containsKey(hash)) {
        _firstSeen[hash] = now;
        _newDeviceTimes.add(now);
      }

      if (name != "Unknown") {
        _nameCounts[name] = (_nameCounts[name] ?? 0) + 1;
      }

      final first = _firstSeen[hash]!;
      if (now.difference(first).inSeconds > LINGER_SECONDS && r.rssi > LINGER_RSSI) {
        if (!_firstSeen.containsKey("${hash}_alerted")) {
          _firstSeen["${hash}_alerted"] = now;
          _triggerAlert(
            "Unknown Device Lingering",
            "Device $name near you for >2 mins, RSSI ${r.rssi} dBm",
            ThreatLevel.watching,
          );
        }
      }
    }

    setState(() {
      devicesLast60s = _newDeviceTimes.length;
      burstsPerSec = _newDeviceTimes.length / 60.0;
    });

    _checkFlood();
    _checkPairSpam();
  }

  void _checkFlood() {
    final now = DateTime.now();
    final count5s = _newDeviceTimes.where((t) => now.difference(t).inSeconds <= 5).length;
    final threshold = isLearning ? 999 : FLOOD_THRESHOLD_5S;

    if (count5s > threshold) {
      _triggerAlert(
        "BLE FLOOD DETECTED",
        "$count5s new devices in 5s — Possible Flipper BLE Spam",
        ThreatLevel.alert,
      );
    }
  }

  void _checkPairSpam() {
    final spamNames = ["AirPods", "Apple TV", "Flipper", "iPhone", "AirTag", "Galaxy Buds"];
    for (final entry in _nameCounts.entries) {
      if (spamNames.any((s) => entry.key.toLowerCase().contains(s.toLowerCase())) &&
          entry.value > PAIR_SPAM_THRESHOLD) {
        _triggerAlert(
          "Pairing Spam",
          "'${entry.key}' seen ${entry.value}x in 10s — Fake pairing attack",
          ThreatLevel.alert,
        );
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
    if (now.second % 10 == 0) {
      _nameCounts.clear();
    }
    setState(() {
      devicesLast60s = _newDeviceTimes.length;
    });
  }

  void _triggerAlert(String title, String detail, ThreatLevel level) {
    setState(() {
      threat = level;
      statusText = title;
    });
    _addLog(title, detail, level);
    if (level == ThreatLevel.alert && !isLearning) {
      _doLockdown(auto: true);
    }
  }

  void _addLog(String title, String detail, ThreatLevel level) {
    setState(() {
      logs.insert(0, LogEvent(time: DateTime.now(), title: title, detail: detail, level: level));
      if (logs.length > 100) logs.removeLast();
    });
  }

  Future<void> _doLockdown({bool auto = false}) async {
    try {
      await FlutterBluePlus.turnOff();
    } catch (e) {}
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
              await FlutterBluePlus.turnOn();
              _addLog("Lockdown Ended", "Bluetooth restored by user", ThreatLevel.safe);
              setState(() { threat = ThreatLevel.safe; statusText = "Protected"; });
            },
            child: const Text("RESTORE NOW"),
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _scanSub?.cancel();
    _cleanupTimer?.cancel();
    FlutterBluePlus.stopScan();
    super.dispose();
  }

  Color _threatColor() {
    switch (threat) {
      case ThreatLevel.safe: return const Color(0xFF00FF88);
      case ThreatLevel.watching: return Colors.amber;
      case ThreatLevel.alert: return Colors.red;
    }
  }

  String _threatLabel() {
    switch (threat) {
      case ThreatLevel.safe: return "PROTECTED";
      case ThreatLevel.watching: return "WATCHING";
      case ThreatLevel.alert: return "ALERT";
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text("FlipperGuard", style: TextStyle(fontWeight: FontWeight.bold)),
        backgroundColor: Colors.transparent,
      ),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
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
            Text(statusText, textAlign: TextAlign.center, style: const TextStyle(color: Colors.white70)),
            const SizedBox(height: 16),
            Row(children: [
              Expanded(child: _statCard("Devices / 60s", "$devicesLast60s")),
              const SizedBox(width: 12),
              Expanded(child: _statCard("Bursts / sec", burstsPerSec.toStringAsFixed(1))),
            ]),
            const SizedBox(height: 16),
            if (!isScanning)
              SizedBox(width: double.infinity, child: ElevatedButton(
                style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF00FF88), padding: const EdgeInsets.symmetric(vertical: 16)),
                onPressed: _requestPermissions,
                child: const Text("ENABLE PROTECTION", style: TextStyle(color: Colors.black, fontWeight: FontWeight.bold)),
              ))
            else
              SizedBox(width: double.infinity, child: ElevatedButton(
                style: ElevatedButton.styleFrom(backgroundColor: Colors.red, padding: const EdgeInsets.symmetric(vertical: 16)),
                onPressed: () => _doLockdown(auto: false),
                child: const Text("LOCKDOWN NOW", style: TextStyle(fontWeight: FontWeight.bold)),
              )),
            const SizedBox(height: 16),
            const Align(alignment: Alignment.centerLeft, child: Text("Recent Events", style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16))),
            const SizedBox(height: 8),
            Expanded(child: ListView.builder(
              itemCount: logs.length,
              itemBuilder: (ctx, i) {
                final e = logs[i];
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
      ),
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