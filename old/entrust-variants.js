#!/usr/bin/env node

import crypto from 'crypto';
import base32Encode from 'base32-encode';

// より実際のEntrust実装に近い可能性のあるバリエーション
function entrustLikeSecret(serial, activationCode, registrationCode, policy = '') {
  console.log('=== Entrust-like implementations ===\n');

  // バリエーション1: バイナリ形式でのパラメータ連結
  console.log('1. Binary parameter concatenation:');
  const serialBytes = Buffer.from(serial.replace(/-/g, ''), 'ascii');
  const activationBytes = Buffer.from(activationCode.replace(/-/g, ''), 'ascii');
  const registrationBytes = Buffer.from(registrationCode.replace(/-/g, ''), 'ascii');

  const combined1 = Buffer.concat([serialBytes, activationBytes, registrationBytes]);
  const hash1 = crypto.createHash('sha1').update(combined1).digest();
  const secret1 = hash1.subarray(0, 20); // SHA1は20バイト、全部使用
  console.log('Secret (20 bytes):', secret1.toString('hex'));
  console.log('Base32:', base32Encode(secret1, 'RFC4648', { padding: false }));

  // バリエーション2: 区切り文字付き
  console.log('\n2. With separators:');
  const combined2 = Buffer.from(`${serial}:${activationCode}:${registrationCode}`);
  const hash2 = crypto.createHash('sha1').update(combined2).digest();
  const secret2 = hash2.subarray(0, 20);
  console.log('Secret (20 bytes):', secret2.toString('hex'));
  console.log('Base32:', base32Encode(secret2, 'RFC4648', { padding: false }));

  // バリエーション3: 大文字変換
  console.log('\n3. Uppercase conversion:');
  const upperSerial = serial.toUpperCase();
  const upperActivation = activationCode.toUpperCase();
  const upperRegistration = registrationCode.toUpperCase();
  const combined3 = Buffer.from(upperSerial.replace(/-/g, '') + upperActivation.replace(/-/g, '') + upperRegistration.replace(/-/g, ''));
  const hash3 = crypto.createHash('sha1').update(combined3).digest();
  const secret3 = hash3.subarray(0, 20);
  console.log('Secret (20 bytes):', secret3.toString('hex'));
  console.log('Base32:', base32Encode(secret3, 'RFC4648', { padding: false }));

  // バリエーション4: MD5使用
  console.log('\n4. MD5 hash:');
  const hash4 = crypto.createHash('md5').update(combined1).digest();
  const secret4 = hash4; // MD5は16バイト
  console.log('Secret (16 bytes):', secret4.toString('hex'));
  console.log('Base32:', base32Encode(secret4, 'RFC4648', { padding: false }));
}

entrustLikeSecret('xxxxx-xxxxx', 'xxxx-xxxx-xxxx-xxxx', 'xxxxx-xxxxx');
