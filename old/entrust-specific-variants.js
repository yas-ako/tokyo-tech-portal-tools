#!/usr/bin/env node

import crypto from 'crypto';
import base32Encode from 'base32-encode';

function parseCode(input) {
  return input.replace(/-/g, '');
}

// より特殊なEntrust固有パターンを生成
function generateEntrustSpecificVariants(serial, activationCode, registrationCode, policy = '') {
  console.log('=== Entrust固有の可能性が高いパターン ===\n');

  const accountName = 'example-account';
  const issuer = 'ExampleIssuer';
  const variants = [];

  // パターン1: Little Endian形式でのバイト順序
  console.log('1. Little Endian バイト順序');
  const data1 = Buffer.concat([
    Buffer.from(parseCode(serial)),
    Buffer.from(parseCode(activationCode)),
    Buffer.from(parseCode(registrationCode))
  ]);
  // バイト順序を逆転
  const reversedData1 = Buffer.from(data1).reverse();
  const hash1 = crypto.createHash('sha1').update(reversedData1).digest();
  const uri1 = generateOtpauthUri(issuer, accountName, hash1, 'SHA1');
  console.log(uri1);
  variants.push({ name: 'Little Endian', uri: uri1 });

  // パターン2: CRC32チェックサム付き
  console.log('\n2. CRC32チェックサム付き（模擬）');
  const crc32 = crypto.createHash('md5').update(data1).digest().subarray(0, 4); // CRC32の代わり
  const dataWithCrc = Buffer.concat([data1, crc32]);
  const hash2 = crypto.createHash('sha1').update(dataWithCrc).digest();
  const uri2 = generateOtpauthUri(issuer, accountName, hash2, 'SHA1');
  console.log(uri2);
  variants.push({ name: 'CRC32付き', uri: uri2 });

  // パターン3: パディング付き（8バイト境界）
  console.log('\n3. 8バイト境界パディング');
  const paddingLength = 8 - (data1.length % 8);
  const paddedData = Buffer.concat([data1, Buffer.alloc(paddingLength, 0)]);
  const hash3 = crypto.createHash('sha1').update(paddedData).digest();
  const uri3 = generateOtpauthUri(issuer, accountName, hash3, 'SHA1');
  console.log(uri3);
  variants.push({ name: '8バイトパディング', uri: uri3 });

  // パターン4: XOR操作付き
  console.log('\n4. XOR操作付き');
  const xorKey = 0xAA; // 一般的なXORキー
  const xorData = Buffer.from(data1.map(byte => byte ^ xorKey));
  const hash4 = crypto.createHash('sha1').update(xorData).digest();
  const uri4 = generateOtpauthUri(issuer, accountName, hash4, 'SHA1');
  console.log(uri4);
  variants.push({ name: 'XOR操作', uri: uri4 });

  // パターン5: 数値として解釈後、バイナリ変換
  console.log('\n5. 数値解釈後バイナリ変換');
  try {
    const numSerial = parseInt(parseCode(serial));
    const numActivation = parseInt(parseCode(activationCode));
    const numRegistration = parseInt(parseCode(registrationCode));

    const binaryData = Buffer.alloc(12); // 4バイト × 3
    binaryData.writeUInt32BE(numSerial, 0);
    binaryData.writeUInt32BE(Math.floor(numActivation / 10000), 4); // 前半
    binaryData.writeUInt32BE(numActivation % 10000 * 10000 + numRegistration, 8); // 後半

    const hash5 = crypto.createHash('sha1').update(binaryData).digest();
    const uri5 = generateOtpauthUri(issuer, accountName, hash5, 'SHA1');
    console.log(uri5);
    variants.push({ name: '数値バイナリ変換', uri: uri5 });
  } catch (e) {
    console.log('数値変換エラー:', e.message);
  }

  // パターン6: HMAC-MD5使用
  console.log('\n6. HMAC-MD5（キーはserial）');
  const hmacKey = Buffer.from(parseCode(serial));
  const hmacData = Buffer.concat([
    Buffer.from(parseCode(activationCode)),
    Buffer.from(parseCode(registrationCode))
  ]);
  const hmac6 = crypto.createHmac('md5', hmacKey).update(hmacData).digest();
  const uri6 = generateOtpauthUri(issuer, accountName, hmac6, 'SHA1');
  console.log(uri6);
  variants.push({ name: 'HMAC-MD5', uri: uri6 });

  // パターン7: 複数回ハッシュ（イテレーション）
  console.log('\n7. 複数回ハッシュ（1000回）');
  let iterativeHash = data1;
  for (let i = 0; i < 1000; i++) {
    iterativeHash = crypto.createHash('sha1').update(iterativeHash).digest();
  }
  const uri7 = generateOtpauthUri(issuer, accountName, iterativeHash, 'SHA1');
  console.log(uri7);
  variants.push({ name: '1000回ハッシュ', uri: uri7 });

  // パターン8: 時刻情報付き（現在の実装では固定値）
  console.log('\n8. 時刻情報付き（UNIX時刻）');
  const timestamp = Math.floor(Date.now() / 1000);
  const timeData = Buffer.concat([data1, Buffer.from(timestamp.toString())]);
  const hash8 = crypto.createHash('sha1').update(timeData).digest();
  const uri8 = generateOtpauthUri(issuer, accountName, hash8, 'SHA1');
  console.log(uri8);
  variants.push({ name: '時刻付き', uri: uri8 });

  // パターン9: 文字列長情報付き
  console.log('\n9. 文字列長情報付き');
  const lengthPrefix = Buffer.alloc(4);
  lengthPrefix.writeUInt32BE(data1.length, 0);
  const lengthData = Buffer.concat([lengthPrefix, data1]);
  const hash9 = crypto.createHash('sha1').update(lengthData).digest();
  const uri9 = generateOtpauthUri(issuer, accountName, hash9, 'SHA1');
  console.log(uri9);
  variants.push({ name: '長さ情報付き', uri: uri9 });

  // パターン10: PBKDF2派生
  console.log('\n10. PBKDF2派生（salt=serial）');
  const salt = Buffer.from(parseCode(serial));
  const password = parseCode(activationCode) + parseCode(registrationCode);
  const pbkdf2Key = crypto.pbkdf2Sync(password, salt, 1000, 20, 'sha1');
  const uri10 = generateOtpauthUri(issuer, accountName, pbkdf2Key, 'SHA1');
  console.log(uri10);
  variants.push({ name: 'PBKDF2派生', uri: uri10 });

  // パターン11: AES暗号化後のキー使用
  console.log('\n11. AES暗号化シミュレーション');
  try {
    const aesKey = crypto.createHash('sha256').update(parseCode(serial)).digest().subarray(0, 16);
    const cipher = crypto.createCipher('aes-128-ecb', aesKey);
    let encrypted = cipher.update(parseCode(activationCode) + parseCode(registrationCode), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const hash11 = crypto.createHash('sha1').update(Buffer.from(encrypted, 'hex')).digest();
    const uri11 = generateOtpauthUri(issuer, accountName, hash11, 'SHA1');
    console.log(uri11);
    variants.push({ name: 'AES暗号化', uri: uri11 });
  } catch (e) {
    console.log('AES暗号化エラー:', e.message);
  }

  // パターン12: ROT13のような文字変換
  console.log('\n12. ROT13文字変換');
  const rot13Transform = (char) => {
    if (char >= '0' && char <= '9') {
      return String.fromCharCode(((char.charCodeAt(0) - '0'.charCodeAt(0) + 5) % 10) + '0'.charCodeAt(0));
    }
    return char;
  };
  const rot13Data = (parseCode(serial) + parseCode(activationCode) + parseCode(registrationCode))
    .split('').map(rot13Transform).join('');
  const hash12 = crypto.createHash('sha1').update(Buffer.from(rot13Data)).digest();
  const uri12 = generateOtpauthUri(issuer, accountName, hash12, 'SHA1');
  console.log(uri12);
  variants.push({ name: 'ROT13変換', uri: uri12 });

  // サマリー
  console.log('\n=== Entrust固有パターン一覧 ===');
  variants.forEach((variant, index) => {
    console.log(`${index + 1}. ${variant.name}`);
    console.log(`   ${variant.uri}\n`);
  });

  return variants;
}

function generateOtpauthUri(issuer, accountName, secretBuffer, algorithm = 'SHA1', digits = 6, period = 30) {
  const secret = base32Encode(secretBuffer, 'RFC4648', { padding: false });
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm,
    digits: digits.toString(),
    period: period.toString(),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

// 実行（機密情報はマスク済み）
const testSerial = 'xxxxx-xxxxx';
const testActivation = 'xxxx-xxxx-xxxx-xxxx';
const testRegistration = 'xxxxx-xxxxx';
const testPolicy = '{"allowUnsecured":"false","trustedExecution":"NOT_ALLOWED"}';

generateEntrustSpecificVariants(testSerial, testActivation, testRegistration, testPolicy);
