#!/usr/bin/env node

import crypto from 'crypto';
import base32Encode from 'base32-encode';

// Python実装との比較テスト
function testPythonCompatibility() {
  console.log('=== Python実装との比較テスト ===\n');

  const serial = 'xxxxx-xxxxx';
  const activationCode = 'xxxx-xxxx-xxxx-xxxx';
  const registrationCode = 'xxxxx-xxxxx';
  const policy = ''; // Python実装では空文字列

  // Step 1: ハイフン除去
  const cleanSerial = serial.replace(/-/g, '');
  const cleanActivation = activationCode.replace(/-/g, '');
  const cleanRegistration = registrationCode.replace(/-/g, '');

  console.log('1. ハイフン除去:');
  console.log('   Serial:', cleanSerial);
  console.log('   Activation:', cleanActivation);
  console.log('   Registration:', cleanRegistration);

  // Step 2: チェックディジット除去
  const activationWithoutCheck = cleanActivation.slice(0, -1);
  const registrationWithoutCheck = cleanRegistration.slice(0, -1);

  console.log('\n2. チェックディジット除去:');
  console.log('   Activation:', activationWithoutCheck);
  console.log('   Registration:', registrationWithoutCheck);

  // Step 3: バイナリ変換
  const activationNum = BigInt(activationWithoutCheck);
  const activationBytes = Buffer.alloc(8);
  activationBytes.writeBigUInt64BE(activationNum, 0);
  const activationBytes7 = activationBytes.subarray(1);

  const registrationNum = parseInt(registrationWithoutCheck);
  const registrationBytes = Buffer.alloc(4);
  registrationBytes.writeUInt32BE(registrationNum, 0);

  console.log('\n3. バイナリ変換:');
  console.log('   Activation (7 bytes):', activationBytes7.toString('hex'));
  console.log('   Registration (4 bytes):', registrationBytes.toString('hex'));

  // Step 4: RNGバイト
  const rngBytes = registrationBytes.subarray(2, 4);
  console.log('\n4. RNGバイト (後ろ2バイト):');
  console.log('   RNG bytes:', rngBytes.toString('hex'));

  // Step 5: パスワード構築
  let password = Buffer.concat([activationBytes7, rngBytes]);
  if (policy && policy.length > 0) {
    password = Buffer.concat([password, Buffer.from(policy, 'utf-8')]);
  }

  console.log('\n5. パスワード:');
  console.log('   Password:', password.toString('hex'));
  console.log('   Password length:', password.length, 'bytes');

  // Step 6: PBKDF2
  const salt = Buffer.from(cleanSerial, 'utf-8');
  const key = crypto.pbkdf2Sync(password, salt, 8, 16, 'sha256');

  console.log('\n6. PBKDF2:');
  console.log('   Salt:', salt.toString('hex'));
  console.log('   Key:', key.toString('hex'));

  // Step 7: Base32エンコード
  const base32Secret = base32Encode(key, 'RFC4648', { padding: false });
  console.log('\n7. Base32エンコード:');
  console.log('   Base32:', base32Secret);

  // Step 8: otpauth URI
  const issuer = 'ExampleIssuer';
  const accountName = 'example-account';
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const params = new URLSearchParams({
    secret: base32Secret,
    issuer: issuer,
    algorithm: 'SHA256',
    digits: '6',
    period: '30',
  });

  const otpauthUri = `otpauth://totp/${label}?${params.toString()}`;

  console.log('\n=== 最終結果 ===');
  console.log('16進数キー:', key.toString('hex'));
  console.log('Base32キー:', base32Secret);
  console.log('otpauth URI:', otpauthUri);

  console.log('\n=== Pythonコマンド比較 ===');
  console.log(`python3 generate_otp.py ${serial} ${activationCode} ${registrationCode}`);
  console.log('Expected hex output:', key.toString('hex'));
}

testPythonCompatibility();
