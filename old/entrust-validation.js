#!/usr/bin/env node

import crypto from 'crypto';
import base32Encode from 'base32-encode';

function parseCode(input) {
  return input.replace(/-/g, '');
}

// Entrust IdentityGuardと同じ実装を再現
function generateEntrustSecret(serial, activationCode, registrationCode) {
  console.log('=== Entrust IdentityGuard 実装再現 ===\n');

  // パラメータ表示
  console.log('入力パラメータ:');
  console.log('Serial:', serial);
  console.log('Activation Code:', activationCode);
  console.log('Registration Code:', registrationCode);

  // ハイフン除去
  const cleanSerial = parseCode(serial);
  const cleanActivation = parseCode(activationCode);
  const cleanRegistration = parseCode(registrationCode);

  console.log('\nハイフン除去後:');
  console.log('Serial:', cleanSerial);
  console.log('Activation Code:', cleanActivation);
  console.log('Registration Code:', cleanRegistration);

  // バッファ連結
  const serialBuf = Buffer.from(cleanSerial);
  const activationBuf = Buffer.from(cleanActivation);
  const registrationBuf = Buffer.from(cleanRegistration);
  const data = Buffer.concat([serialBuf, activationBuf, registrationBuf]);

  console.log('\n連結データ:');
  console.log('文字列:', data.toString());
  console.log('16進数:', data.toString('hex'));
  console.log('データ長:', data.length, 'バイト');

  // SHA256ハッシュ（16バイト）
  const hash = crypto.createHash('sha256').update(data).digest();
  const secret16 = hash.subarray(0, 16);

  console.log('\nSHA256ハッシュ:');
  console.log('フルハッシュ(32バイト):', hash.toString('hex'));
  console.log('16バイト切り取り:', secret16.toString('hex'));

  // Base32エンコード
  const base32Secret = base32Encode(secret16, 'RFC4648', { padding: false });
  console.log('\nBase32エンコード:');
  console.log('Base32:', base32Secret);

  // otpauth URI生成
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
  console.log('16進数シークレット:', secret16.toString('hex'));
  console.log('Base32シークレット:', base32Secret);
  console.log('otpauth URI:', otpauthUri);

  // ターミナルコマンドも表示
  console.log('\n=== ターミナルでBase32変換確認コマンド ===');
  console.log(`echo "${secret16.toString('hex')}" | tr [:lower:] [:upper:] | xxd -r -p | base32`);

  return {
    hexSecret: secret16.toString('hex'),
    base32Secret: base32Secret,
    otpauthUri: otpauthUri
  };
}

// テスト実行
const result = generateEntrustSecret('xxxxx-xxxxx', 'xxxx-xxxx-xxxx-xxxx', 'xxxxx-xxxxx');
