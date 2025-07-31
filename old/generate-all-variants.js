#!/usr/bin/env node

import crypto from 'crypto';
import base32Encode from 'base32-encode';

function parseCode(input) {
  return input.replace(/-/g, '');
}

// 様々なパターンでotpauth URIを生成
function generateAllVariants(serial, activationCode, registrationCode, policy = '') {
  console.log('=== 考えられるotpauth URIの全パターン ===\n');

  const variants = [];

  // 基本パラメータ
  const accountName = 'example-account';
  const issuer = 'ExampleIssuer';

  // パターン1: オリジナル実装（SHA256, 16バイト, ポリシーなし）
  console.log('1. オリジナル実装（SHA256, 16バイト, ポリシーなし）');
  const data1 = Buffer.concat([
    Buffer.from(parseCode(serial)),
    Buffer.from(parseCode(activationCode)),
    Buffer.from(parseCode(registrationCode))
  ]);
  const hash1 = crypto.createHash('sha256').update(data1).digest();
  const secret1 = hash1.subarray(0, 16);
  const uri1 = generateOtpauthUri(issuer, accountName, secret1, 'SHA256');
  console.log(uri1);
  variants.push({ name: 'オリジナル(SHA256,16byte)', uri: uri1 });

  // パターン2: 修正版（SHA1, 20バイト, ポリシー含む）
  console.log('\n2. 修正版（SHA1, 20バイト, ポリシー含む）');
  const data2 = Buffer.concat([
    Buffer.from(parseCode(serial)),
    Buffer.from(parseCode(activationCode)),
    Buffer.from(parseCode(registrationCode)),
    Buffer.from(policy)
  ]);
  const hash2 = crypto.createHash('sha1').update(data2).digest();
  const uri2 = generateOtpauthUri(issuer, accountName, hash2, 'SHA1');
  console.log(uri2);
  variants.push({ name: '修正版(SHA1,20byte,ポリシー含む)', uri: uri2 });

  // パターン3: SHA1, 16バイト, ポリシーなし
  console.log('\n3. SHA1, 16バイト, ポリシーなし');
  const hash3 = crypto.createHash('sha1').update(data1).digest();
  const secret3 = hash3.subarray(0, 16);
  const uri3 = generateOtpauthUri(issuer, accountName, secret3, 'SHA1');
  console.log(uri3);
  variants.push({ name: 'SHA1,16byte,ポリシーなし', uri: uri3 });

  // パターン4: SHA1, 20バイト, ポリシーなし
  console.log('\n4. SHA1, 20バイト, ポリシーなし');
  const uri4 = generateOtpauthUri(issuer, accountName, hash3, 'SHA1');
  console.log(uri4);
  variants.push({ name: 'SHA1,20byte,ポリシーなし', uri: uri4 });

  // パターン5: MD5ハッシュ
  console.log('\n5. MD5ハッシュ（16バイト）');
  const hash5 = crypto.createHash('md5').update(data1).digest();
  const uri5 = generateOtpauthUri(issuer, accountName, hash5, 'SHA1');
  console.log(uri5);
  variants.push({ name: 'MD5,16byte', uri: uri5 });

  // パターン6: 区切り文字付き
  console.log('\n6. 区切り文字付きデータ（コロン区切り）');
  const data6 = Buffer.from(`${serial}:${activationCode}:${registrationCode}`);
  const hash6 = crypto.createHash('sha1').update(data6).digest();
  const uri6 = generateOtpauthUri(issuer, accountName, hash6, 'SHA1');
  console.log(uri6);
  variants.push({ name: 'コロン区切り', uri: uri6 });

  // パターン7: 大文字変換
  console.log('\n7. 大文字変換');
  const data7 = Buffer.from((serial + activationCode + registrationCode).toUpperCase().replace(/-/g, ''));
  const hash7 = crypto.createHash('sha1').update(data7).digest();
  const uri7 = generateOtpauthUri(issuer, accountName, hash7, 'SHA1');
  console.log(uri7);
  variants.push({ name: '大文字変換', uri: uri7 });

  // パターン8: 順序変更（registrationCode → activationCode → serial）
  console.log('\n8. パラメータ順序変更（reg→act→ser）');
  const data8 = Buffer.concat([
    Buffer.from(parseCode(registrationCode)),
    Buffer.from(parseCode(activationCode)),
    Buffer.from(parseCode(serial))
  ]);
  const hash8 = crypto.createHash('sha1').update(data8).digest();
  const uri8 = generateOtpauthUri(issuer, accountName, hash8, 'SHA1');
  console.log(uri8);
  variants.push({ name: 'パラメータ順序変更', uri: uri8 });

  // パターン9: 16進数文字列として連結
  console.log('\n9. 16進数文字列として連結');
  const hexString = Buffer.from(parseCode(serial)).toString('hex') +
    Buffer.from(parseCode(activationCode)).toString('hex') +
    Buffer.from(parseCode(registrationCode)).toString('hex');
  const data9 = Buffer.from(hexString, 'hex');
  const hash9 = crypto.createHash('sha1').update(data9).digest();
  const uri9 = generateOtpauthUri(issuer, accountName, hash9, 'SHA1');
  console.log(uri9);
  variants.push({ name: '16進数連結', uri: uri9 });

  // パターン10: UTF-8エンコーディング指定
  console.log('\n10. UTF-8エンコーディング明示');
  const data10 = Buffer.concat([
    Buffer.from(parseCode(serial), 'utf8'),
    Buffer.from(parseCode(activationCode), 'utf8'),
    Buffer.from(parseCode(registrationCode), 'utf8')
  ]);
  const hash10 = crypto.createHash('sha1').update(data10).digest();
  const uri10 = generateOtpauthUri(issuer, accountName, hash10, 'SHA1');
  console.log(uri10);
  variants.push({ name: 'UTF-8明示', uri: uri10 });

  // パターン11: Base64エンコードされた値を使用
  console.log('\n11. Base64エンコード経由');
  const base64Data = Buffer.from(data1.toString('base64')).toString();
  const data11 = Buffer.from(base64Data);
  const hash11 = crypto.createHash('sha1').update(data11).digest();
  const uri11 = generateOtpauthUri(issuer, accountName, hash11, 'SHA1');
  console.log(uri11);
  variants.push({ name: 'Base64経由', uri: uri11 });

  // パターン12: ハイフン付きのまま処理
  console.log('\n12. ハイフン付きのまま処理');
  const data12 = Buffer.from(serial + activationCode + registrationCode);
  const hash12 = crypto.createHash('sha1').update(data12).digest();
  const uri12 = generateOtpauthUri(issuer, accountName, hash12, 'SHA1');
  console.log(uri12);
  variants.push({ name: 'ハイフン付き', uri: uri12 });

  // パターン13: 異なるアルゴリズム（SHA256でも20バイト）
  console.log('\n13. SHA256で20バイト');
  const hash13 = crypto.createHash('sha256').update(data1).digest();
  const secret13 = hash13.subarray(0, 20);
  const uri13 = generateOtpauthUri(issuer, accountName, secret13, 'SHA256');
  console.log(uri13);
  variants.push({ name: 'SHA256,20byte', uri: uri13 });

  // パターン14: SHA512使用
  console.log('\n14. SHA512で20バイト');
  const hash14 = crypto.createHash('sha512').update(data1).digest();
  const secret14 = hash14.subarray(0, 20);
  const uri14 = generateOtpauthUri(issuer, accountName, secret14, 'SHA512');
  console.log(uri14);
  variants.push({ name: 'SHA512,20byte', uri: uri14 });

  // パターン15: 8桁コード
  console.log('\n15. 8桁コード');
  const uri15 = generateOtpauthUri(issuer, accountName, hash2, 'SHA1', 8);
  console.log(uri15);
  variants.push({ name: '8桁コード', uri: uri15 });

  // パターン16: 60秒間隔
  console.log('\n16. 60秒間隔');
  const uri16 = generateOtpauthUri(issuer, accountName, hash2, 'SHA1', 6, 60);
  console.log(uri16);
  variants.push({ name: '60秒間隔', uri: uri16 });

  // サマリー出力
  console.log('\n=== 生成されたURI一覧 ===');
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

// 実行
const testSerial = 'xxxxx-xxxxx';
const testActivation = 'xxxx-xxxx-xxxx-xxxx';
const testRegistration = 'xxxxx-xxxxx';
const testPolicy = '{"allowUnsecured":"false","trustedExecution":"NOT_ALLOWED"}';

generateAllVariants(testSerial, testActivation, testRegistration, testPolicy);
