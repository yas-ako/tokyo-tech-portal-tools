#!/usr/bin/env node

import crypto from 'crypto';
import base32Encode from 'base32-encode';

function parseCode(input) {
  return input.replace(/-/g, '');
}

// 複数のバリエーションを試すテスト
function testDifferentApproaches(serial, activationCode, registrationCode, policy = '') {
  console.log('Testing different secret generation approaches:\n');

  // アプローチ1: 現在の実装（ポリシー含む）
  console.log('=== Approach 1: With Policy ===');
  const serialBuf = Buffer.from(parseCode(serial));
  const activationBuf = Buffer.from(parseCode(activationCode));
  const registrationBuf = Buffer.from(parseCode(registrationCode));
  const policyBuf = policy ? Buffer.from(policy) : Buffer.alloc(0);

  const data1 = Buffer.concat([serialBuf, activationBuf, registrationBuf, policyBuf]);
  const hash1 = crypto.createHash('sha256').update(data1).digest();
  const secret1 = hash1.subarray(0, 16);
  console.log('Secret:', secret1.toString('hex'));
  console.log('Base32:', base32Encode(secret1, 'RFC4648', { padding: false }));

  // アプローチ2: 16進数として連結
  console.log('\n=== Approach 2: Hex concatenation ===');
  const serialHex = Buffer.from(parseCode(serial)).toString('hex');
  const activationHex = Buffer.from(parseCode(activationCode)).toString('hex');
  const registrationHex = Buffer.from(parseCode(registrationCode)).toString('hex');

  const hexString = serialHex + activationHex + registrationHex;
  const data2 = Buffer.from(hexString, 'hex');
  const hash2 = crypto.createHash('sha256').update(data2).digest();
  const secret2 = hash2.subarray(0, 16);
  console.log('Secret:', secret2.toString('hex'));
  console.log('Base32:', base32Encode(secret2, 'RFC4648', { padding: false }));

  // アプローチ3: 数値として扱う
  console.log('\n=== Approach 3: Numeric values ===');
  const serialNum = parseCode(serial);
  const activationNum = parseCode(activationCode);
  const registrationNum = parseCode(registrationCode);

  const numString = serialNum + activationNum + registrationNum;
  const data3 = Buffer.from(numString);
  const hash3 = crypto.createHash('sha256').update(data3).digest();
  const secret3 = hash3.subarray(0, 16);
  console.log('Secret:', secret3.toString('hex'));
  console.log('Base32:', base32Encode(secret3, 'RFC4648', { padding: false }));

  // アプローチ4: 異なる順序
  console.log('\n=== Approach 4: Different order (registration first) ===');
  const data4 = Buffer.concat([registrationBuf, activationBuf, serialBuf]);
  const hash4 = crypto.createHash('sha256').update(data4).digest();
  const secret4 = hash4.subarray(0, 16);
  console.log('Secret:', secret4.toString('hex'));
  console.log('Base32:', base32Encode(secret4, 'RFC4648', { padding: false }));

  // アプローチ5: SHA1を使用
  console.log('\n=== Approach 5: SHA1 instead of SHA256 ===');
  const hash5 = crypto.createHash('sha1').update(data1).digest();
  const secret5 = hash5.subarray(0, 16);
  console.log('Secret:', secret5.toString('hex'));
  console.log('Base32:', base32Encode(secret5, 'RFC4648', { padding: false }));
}

// 実際の値でテスト
// テスト実行（実際の値はマスクされています）
testDifferentApproaches('xxxxx-xxxxx', 'xxxx-xxxx-xxxx-xxxx', 'xxxxx-xxxxx', '{"allowUnsecured":"false","trustedExecution":"NOT_ALLOWED"}');
