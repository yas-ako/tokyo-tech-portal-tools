#!/usr/bin/env node

import crypto from 'crypto';
import base32Encode from 'base32-encode';

// デバッグ用の関数
function parseCode(input) {
  return input.replace(/-/g, '');
}

function generateOtpSecret(serial, activationCode, registrationCode, policy = '') {
  console.log('Input parameters:');
  console.log('Serial:', serial);
  console.log('Activation Code:', activationCode);
  console.log('Registration Code:', registrationCode);
  console.log('Policy:', policy);

  const serialBuf = Buffer.from(parseCode(serial));
  const activationBuf = Buffer.from(parseCode(activationCode));
  const registrationBuf = Buffer.from(parseCode(registrationCode));

  console.log('\nParsed codes:');
  console.log('Serial (no hyphens):', parseCode(serial));
  console.log('Activation (no hyphens):', parseCode(activationCode));
  console.log('Registration (no hyphens):', parseCode(registrationCode));

  const data = Buffer.concat([serialBuf, activationBuf, registrationBuf]);
  console.log('\nConcatenated data:', data.toString());
  console.log('Data hex:', data.toString('hex'));
  console.log('Data length:', data.length);

  const hash = crypto.createHash('sha256').update(data).digest();
  console.log('\nSHA256 hash (full):', hash.toString('hex'));

  const secret = hash.subarray(0, 16);
  console.log('Secret (16 bytes):', secret.toString('hex'));
  console.log('Secret base32:', base32Encode(secret, 'RFC4648', { padding: false }));

  return secret;
}

// TOTP計算のテスト
function calculateTOTP(secret, timeStep = 30) {
  const now = Math.floor(Date.now() / 1000);
  const timeCounter = Math.floor(now / timeStep);

  console.log('\nTOTP calculation:');
  console.log('Current timestamp:', now);
  console.log('Time counter:', timeCounter);
  console.log('Time counter hex:', timeCounter.toString(16).padStart(16, '0'));

  // HMAC-SHA1計算（TOTPの標準）
  const timeBuffer = Buffer.alloc(8);
  timeBuffer.writeUInt32BE(Math.floor(timeCounter / 0x100000000), 0);
  timeBuffer.writeUInt32BE(timeCounter & 0xffffffff, 4);

  const hmac = crypto.createHmac('sha1', secret);
  hmac.update(timeBuffer);
  const hash = hmac.digest();

  console.log('HMAC-SHA1 hash:', hash.toString('hex'));

  // Dynamic truncation
  const offset = hash[hash.length - 1] & 0xf;
  const code = (
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff)
  ) % 1000000;

  console.log('Generated TOTP code:', code.toString().padStart(6, '0'));

  return code;
}

// テスト実行
const secret = generateOtpSecret('xxxxx-xxxxx', 'xxxx-xxxx-xxxx-xxxx', 'xxxxx-xxxxx');
calculateTOTP(secret);
