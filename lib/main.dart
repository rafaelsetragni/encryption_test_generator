import 'package:encrypt/encrypt.dart' as symmetric;
import 'package:fast_rsa/fast_rsa.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:pretty_qr_code/pretty_qr_code.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      home: KeyGeneratorScreen(),
    );
  }
}

class KeyGeneratorScreen extends StatefulWidget {
  const KeyGeneratorScreen({super.key});

  @override
  State<KeyGeneratorScreen> createState() => _KeyGeneratorScreenState();
}

class _KeyGeneratorScreenState extends State<KeyGeneratorScreen> {
  final GlobalKey<FormState> formKey = GlobalKey();

  static final List<int> privateKeySizes = [1024, 2048, 4096];
  int? selectedKeySize = privateKeySizes.first;

  static final List<int> symmetricSecretSize = [128, 192, 256];
  int? selectedSecretSize = symmetricSecretSize.first;

  static const List<symmetric.AESMode> aesAlgorithms = symmetric.AESMode.values;
  symmetric.AESMode? selectedAesAlgorithm = aesAlgorithms.first;

  // Controllers for user inputs and encrypted outputs
  static final List<String> fieldNames = [
    "secret",
    "title",
    "body",
    "summary",
    "largeIcon",
    "bigPicture",
  ];

  final Map<String, TextEditingController> fieldControllers = {
    for (String fieldName in fieldNames) fieldName: TextEditingController(),
  };

  final Map<String, TextEditingController> encryptedControllers = {
    for (String fieldName in fieldNames) fieldName: TextEditingController(),
  };

  TextEditingController privateKeyController = TextEditingController();
  TextEditingController publicKeyController = TextEditingController();

  String get privateKey => privateKeyController.text;

  set privateKey(String value) => privateKeyController.text = value;

  String get publicKey => publicKeyController.text;

  set publicKey(String value) => publicKeyController.text = value;

  String get symmetricSecret => fieldControllers['secret']!.text;

  set symmetricSecret(String value) => fieldControllers['secret']!.text = value;

  QrImage? privateKeyImage;
  QrImage? publicKeyImage;

  Future<void> generateKeyPair() async {
    final selectedKeySize = this.selectedKeySize;
    if (selectedKeySize == null) return;

    final keyPair = await RSA.generate(selectedKeySize);
    privateKeyController.text =
        await RSA.convertPrivateKeyToPKCS1(keyPair.privateKey);
    publicKeyController.text =
        await RSA.convertPublicKeyToPKCS1(keyPair.publicKey);

    setState(() {});
  }

  Future<void> generateNewRandomSymmetricSecret() async {
    final secretSize = selectedSecretSize;
    symmetricSecret = secretSize == null
        ? ''
        : symmetric.Key.fromLength(secretSize ~/ 8).base64;
    encryptedControllers['secret']?.text = '';
  }

  Future<void> encryptTexts() async {
    if (symmetricSecret.isEmpty) generateNewRandomSymmetricSecret();

    for (int index = 0; index < fieldNames.length; index++) {
      final fieldName = fieldNames.elementAt(index);
      final fieldController = fieldControllers[fieldName];
      final encryptedController = encryptedControllers[fieldName];
      final originalValue = fieldController?.text;

      if (originalValue == null) continue;
      if (fieldController == null) continue;
      if (encryptedController == null) continue;

      late final String encryptedValue;
      if (originalValue.isEmpty) {
        encryptedValue = '';
      } else if (fieldName == 'secret') {
        encryptedValue = await encryptTextWithAsymmetricKey(
          publicKey: publicKeyController.text,
          text: symmetricSecret,
        );
      } else {
        encryptedValue = await encryptTextWithSymmetricSecret(
          secret: symmetricSecret,
          text: originalValue,
        );
      }
      encryptedControllers[fieldName]?.text = encryptedValue;
    }

    setState(() {});
  }

  Future<void> setDefaultValues() async {
    if (symmetricSecret.isEmpty) generateNewRandomSymmetricSecret();

    for (int index = 0; index < fieldNames.length; index++) {
      final fieldName = fieldNames.elementAt(index);
      final fieldController = fieldControllers[fieldName];
      final encryptedController = encryptedControllers[fieldName];
      final originalValue = fieldController?.text;

      if (fieldName == 'secret') continue;
      if (originalValue == null) continue;
      if (fieldController == null) continue;
      if (encryptedController == null) continue;

      final String fieldValue = switch (fieldName) {
        'title' => 'Jimmy Smithy',
        'body' => 'This is a secret message',
        'summary' => 'Secret group',
        'largeIcon' =>
          'https://t3.ftcdn.net/jpg/06/16/17/86/360_F_616178696_5McM57f04Ps'
              'CCte3TKq1TKHvnNKJP6cu.jpg',
        'bigPicture' =>
          'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSK1kuze2R6'
              'BzalLy5WO_UyJq1hjseF_L5McA&s',
        _ => throw Exception('field not found'),
      };
      fieldControllers[fieldName]?.text = fieldValue;
    }

    setState(() {});
  }

  Future<String> encryptTextWithAsymmetricKey({
    required String publicKey,
    required String text,
  }) async {
    return await RSA.encryptPKCS1v15(text, publicKey);
  }

  Future<String> encryptTextWithSymmetricSecret({
    required String secret,
    required String text,
  }) async {
    final secretSize = selectedSecretSize;
    if (secretSize == null) return '';
    if (publicKeyController.text.isEmpty) return '';
    if (publicKeyController.text.isEmpty) return '';
    if (text.isEmpty) return '';

    final symmetricKey = symmetric.Key.fromBase64(secret);
    final iv = symmetric.IV.fromLength(secretSize ~/ 16);
    final builder = symmetric.Encrypter(symmetric.AES(
      symmetricKey,
      mode: symmetric.AESMode.gcm,
      padding: null,
    ));
    final encrypted = builder.encrypt(text, iv: iv);
    return encrypted.base64;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text("RSA Key Generator"),
      ),
      body: SingleChildScrollView(
        child: Form(
          key: formKey,
          child: Padding(
            padding: const EdgeInsets.all(16.0),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                DropdownButtonFormField<int>(
                  value: selectedKeySize,
                  decoration: const InputDecoration(
                      labelText: "Select Private Key Size"),
                  onChanged: (int? newValue) {
                    setState(() {
                      selectedKeySize = newValue;
                    });
                  },
                  items: privateKeySizes
                      .map((size) => DropdownMenuItem<int>(
                            value: size,
                            child: Text("$size bits"),
                          ))
                      .toList(),
                ),
                const SizedBox(height: 20),
                DropdownButtonFormField<symmetric.AESMode>(
                  value: selectedAesAlgorithm,
                  decoration: const InputDecoration(
                      labelText: "Symmetric AES Algorithm"),
                  onChanged: (symmetric.AESMode? newValue) {
                    setState(() {
                      selectedAesAlgorithm = newValue;
                    });
                  },
                  items: aesAlgorithms
                      .map((aesMode) => DropdownMenuItem<symmetric.AESMode>(
                            value: aesMode,
                            child: Text(aesMode.name),
                          ))
                      .toList(),
                ),
                const SizedBox(height: 20),
                DropdownButtonFormField<int>(
                  value: selectedSecretSize,
                  decoration:
                      const InputDecoration(labelText: "Symmetric Secret Size"),
                  onChanged: (int? newValue) {
                    setState(() {
                      selectedSecretSize = newValue;
                      symmetricSecret = '';
                    });
                  },
                  items: symmetricSecretSize
                      .map((size) => DropdownMenuItem<int>(
                            value: size,
                            child: Text("$size bits"),
                          ))
                      .toList(),
                ),
                const SizedBox(height: 20),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: [
                    ElevatedButton(
                      onPressed: generateKeyPair,
                      child: const Text('Generate Keys'),
                    ),
                    const ElevatedButton(
                      onPressed: null,
                      child: Text('Insert Private Key'),
                    ),
                    const ElevatedButton(
                      onPressed: null,
                      child: Text('Insert Public Key'),
                    ),
                  ],
                ),
                const SizedBox(height: 20),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: [
                    QrCodeWidget(
                      label: 'Private Key',
                      content: privateKeyController.text,
                    ),
                    QrCodeWidget(
                      label: 'Public Key',
                      content: publicKeyController.text,
                    ),
                  ],
                ),
                const SizedBox(height: 40),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: [
                    ElevatedButton(
                      onPressed: generateNewRandomSymmetricSecret,
                      child: const Text('Generate new Secret'),
                    ),
                    ElevatedButton(
                      onPressed: setDefaultValues,
                      child: const Text('Set default values'),
                    ),
                  ],
                ),
                Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      ...fieldControllers.keys.map(
                        (key) => Padding(
                          padding: const EdgeInsets.only(bottom: 10.0),
                          child: Row(
                            children: [
                              Expanded(
                                child: TextFormField(
                                  controller: fieldControllers[key],
                                  decoration: InputDecoration(
                                    labelText:
                                        "${key[0].toUpperCase()}${key.substring(1)}",
                                    border: const OutlineInputBorder(),
                                  ),
                                ),
                              ),
                              const SizedBox(width: 10),
                              Expanded(
                                child: TextFormField(
                                  controller: encryptedControllers[key],
                                  decoration: InputDecoration(
                                    labelText:
                                        "Encrypted ${key[0].toUpperCase()}${key.substring(1)}",
                                    border: const OutlineInputBorder(),
                                  ),
                                  readOnly: true,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          ElevatedButton(
                            onPressed: encryptTexts,
                            child: const Text('Encrypt text'),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class QrCodeWidget extends StatefulWidget {
  const QrCodeWidget({
    super.key,
    required String content,
    required this.label,
    this.width = 250.0,
  }) : content = content.length > 1024 ? 'value too long' : content;

  final String content;
  final double width;
  final String label;

  @override
  State<QrCodeWidget> createState() => _QrCodeWidgetState();
}

class _QrCodeWidgetState extends State<QrCodeWidget> {
  static final QrImage defaultQrCodeImage = QrImage(QrCode(
    8,
    QrErrorCorrectLevel.H,
  )..addData('lorem ipsum dolor sit amet'));

  QrImage? qrImage;

  @override
  void didUpdateWidget(covariant QrCodeWidget oldWidget) {
    qrImage = QrImage(QrCode.fromData(
      data: widget.content,
      errorCorrectLevel: QrErrorCorrectLevel.H,
    ));
    super.didUpdateWidget(oldWidget);
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Text(
          widget.label,
          style: const TextStyle(fontWeight: FontWeight.bold),
        ),
        const SizedBox(height: 12),
        SizedBox(
          width: widget.width,
          height: widget.width,
          child: Opacity(
            opacity: widget.content.isNotEmpty ? 1.0 : 0.3,
            child: PrettyQrView(
              qrImage: qrImage ?? defaultQrCodeImage,
              decoration: const PrettyQrDecoration(),
            ),
          ),
        ),
        const SizedBox(height: 12),
        ElevatedButton(
          onPressed: () {
            Clipboard.setData(ClipboardData(text: widget.content));
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(
                content: Text('Content copied to clipboard!'),
                duration: Duration(seconds: 2),
              ),
            );
          },
          child: const Text('Copy to Clipboard'),
        ),
      ],
    );
  }
}
