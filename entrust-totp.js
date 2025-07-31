#!/usr/bin/env node

import { config } from 'dotenv';
import crypto from 'crypto';
import base32Encode from 'base32-encode';

config();

/**
 * @fileoverview Entrust IdentityGuard TOTP認証URI生成ツール
 * @description シリアル番号、アクティベーションコード、登録コードからTOTP（Time-based One-Time Password）の認証URIを生成します。
 * 
 * @example
 * // 基本的な使い方
 * node entrust-totp.js <serial> <activationCode> <registrationCode> <accountName> [issuer]
 * 
 * @example
 * // 環境変数を使用する場合（.envファイルに設定）
 * node entrust-totp.js
 */

/**
 * ハイフンを削除
 * @param {string} input - ハイフン区切りの文字列
 * @returns {string} - ハイフンを削除した文字列
 */
function parseCode(input) {
  return input.replace(/-/g, '');
}

/**
 * Entrust IdentityGuard仕様に準拠したOTPシークレットを生成
 * @param {string} serial - シリアル番号
 * @param {string} activationCode - アクティベーションコード
 * @param {string} registrationCode - 登録コード
 * @param {string} [policy=''] - セキュリティポリシー（通常は空文字列）
 * @returns {Buffer} - OTPシークレット（16バイト）
 */
function generateOtpSecret(serial, activationCode, registrationCode, policy = '') {
  // ハイフン除去
  const cleanSerial = parseCode(serial);
  const cleanActivation = parseCode(activationCode);
  const cleanRegistration = parseCode(registrationCode);

  // チェックディジット除去（最後の桁）
  const activationWithoutCheck = cleanActivation.slice(0, -1);
  const registrationWithoutCheck = cleanRegistration.slice(0, -1);

  // アクティベーションコードを7バイトのbig-endianに変換
  const activationNum = BigInt(activationWithoutCheck);
  const activationBytes = Buffer.alloc(8);
  activationBytes.writeBigUInt64BE(activationNum, 0);
  const activationBytes7 = activationBytes.subarray(1); // 先頭1バイト除去で7バイト

  // 登録コードを4バイトのbig-endianに変換
  const registrationNum = parseInt(registrationWithoutCheck);
  const registrationBytes = Buffer.alloc(4);
  registrationBytes.writeUInt32BE(registrationNum, 0);

  // RNGバイト（登録コードの後ろ2バイト）
  const rngBytes = registrationBytes.subarray(2, 4);

  // パスワード = activationBytes + rngBytes (+ policy)
  let password = Buffer.concat([activationBytes7, rngBytes]);
  if (policy && policy.length > 0) {
    password = Buffer.concat([password, Buffer.from(policy, 'utf-8')]);
  }

  // PBKDF2でキー導出（Entrust IdentityGuard仕様）
  const salt = Buffer.from(cleanSerial, 'utf-8');
  const key = crypto.pbkdf2Sync(password, salt, 8, 16, 'sha256');

  return key;
}

/**
 * otpauth URI を生成
 * @param {string} issuer - 発行者名
 * @param {string} accountName - アカウント名
 * @param {Buffer} secretBuffer - OTPシークレット（バッファ）
 * @returns {string} - otpauth URI
 */
function generateOtpauthUri(issuer, accountName, secretBuffer) {
  // Base32エンコード（RFC 4648、パディングなし）
  const secret = base32Encode(secretBuffer, 'RFC4648', { padding: false });

  // ラベルのエンコード（issuer:accountName）
  const label = encodeURIComponent(`${issuer}:${accountName}`);

  // パラメータのエンコード
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA256',
    digits: '6',
    period: '30',
  });

  return `otpauth://totp/${label}?${params.toString()}`;
}

// メイン処理
function main() {
  const args = process.argv.slice(2);

  // 環境変数から値を取得
  const serial = args[0] || process.env.SERIAL;
  const activationCode = args[1] || process.env.ACTIVATION_CODE;
  const registrationCode = args[2] || process.env.REGISTRATION_CODE;
  const accountName = args[3] || process.env.ACCOUNT_NAME;
  const issuer = args[4] || process.env.ISSUER || 'Entrust';

  if (!serial || !activationCode || !registrationCode || !accountName) {
    console.error('エラー: 必要なパラメータが不足しています。');
    console.error('');
    console.error('使用方法:');
    console.error('  node entrust-totp.js <serial> <activationCode> <registrationCode> <accountName> [issuer]');
    console.error('');
    console.error('または、.envファイルに以下の環境変数を設定してください:');
    console.error('  SERIAL=your-serial-number');
    console.error('  ACTIVATION_CODE=your-activation-code');
    console.error('  REGISTRATION_CODE=your-registration-code');
    console.error('  ACCOUNT_NAME=your-account-name');
    console.error('  ISSUER=your-issuer-name (オプション)');
    process.exit(1);
  }

  try {
    const otpSecretBuffer = generateOtpSecret(serial, activationCode, registrationCode);
    const otpauthUri = generateOtpauthUri(issuer, accountName, otpSecretBuffer);

    console.log('TOTP認証URI が正常に生成されました:');
    console.log('');
    console.log(otpauthUri);
    console.log('');
    console.log('このURIをGoogle AuthenticatorやAuthy等のTOTPアプリに追加してください。');
  } catch (error) {
    console.error('エラー: TOTP URI の生成に失敗しました:', error.message);
    process.exit(1);
  }
}

// スクリプトとして実行された場合にメイン処理を実行
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { generateOtpSecret, generateOtpauthUri };
