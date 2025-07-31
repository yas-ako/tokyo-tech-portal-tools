#!/usr/bin/env node

import { config } from 'dotenv';
import crypto from 'crypto';
import base32Encode from 'base32-encode';

config();

/**
 * @fileoverview TOTP認証URI生成スクリプト
 * @description シリアル番号、アクティベーションコード、登録コードからTOTP（Time-based One-Time Password）の認証URIを生成します。
 * 
 * @example
 * // 基本的な使い方
 * node generate-otpauth-uri.js <serial> <activationCode> <registrationCode> <accountName> [policy] [issuer] [algorithm] [digits] [period]
 * 
 * @example
 * // 環境変数を使用する場合
 * // .envファイルに以下の変数を設定
 * // SERIAL=xxxxx-xxxxx
 * // ACTIVATION_CODE=xxxx-xxxx-xxxx-xxxx
 * // REGISTRATION_CODE=xxxxx-xxxxx
 * // ACCOUNT_NAME=alice@example.com
 * // POLICY={"allowUnsecured":"false","trustedExecution":"NOT_ALLOWED"}
 * // ISSUER=ExampleCorp
 * // ALGORITHM=SHA256
 * // DIGITS=6
 * // PERIOD=30
 * 
 * @param {string} serial - シリアル番号（例：xxxxx-xxxxx）
 * @param {string} activationCode - アクティベーションコード（例：xxxx-xxxx-xxxx-xxxx）
 * @param {string} registrationCode - 登録コード（例：xxxxx-xxxxx）
 * @param {string} accountName - アカウント名（例：alice@example.com）
 * @param {string} [policy=''] - セキュリティポリシー（JSON形式）
 * @param {string} [issuer='ExampleIssuer'] - 発行者名
 * @param {string} [algorithm='SHA256'] - ハッシュアルゴリズム
 * @param {number} [digits=6] - OTPの桁数
 * @param {number} [period=30] - 有効期間（秒単位）
 * 
 * @returns {void} 生成されたotpauth URIを標準出力に表示します。
 * このURIはGoogle AuthenticatorなどのTOTP認証アプリで使用できます。
 */

/**
 * ハイフンを削除し、文字列として結合
 * @param {string} input - ハイフン区切りの文字列
 * @returns {string} - ハイフンを削除した文字列
 */
function parseCode(input) {
  return input.replace(/-/g, '');
}

/**
 * OTP シークレットを生成（Entrust IdentityGuard実装準拠）
 * @param {string} serial - シリアル番号
 * @param {string} activationCode - アクティベーションコード
 * @param {string} registrationCode - 登録コード
 * @param {string} [policy] - ポリシー（オプション）
 * @returns {Buffer} - OTP シークレット（バッファ）
 */
function generateOtpSecret(serial, activationCode, registrationCode, policy = '') {
  // ハイフン除去
  const cleanSerial = parseCode(serial);
  const cleanActivation = parseCode(activationCode);
  const cleanRegistration = parseCode(registrationCode);

  // チェックディジット除去（最後の桁）
  const activationWithoutCheck = cleanActivation.slice(0, -1);
  const registrationWithoutCheck = cleanRegistration.slice(0, -1);

  console.log('Debug - Clean serial:', cleanSerial);
  console.log('Debug - Activation without check digit:', activationWithoutCheck);
  console.log('Debug - Registration without check digit:', registrationWithoutCheck);

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

  console.log('Debug - Activation bytes (7):', activationBytes7.toString('hex'));
  console.log('Debug - Registration bytes (4):', registrationBytes.toString('hex'));
  console.log('Debug - RNG bytes (2):', rngBytes.toString('hex'));

  // パスワード = activationBytes + rngBytes (+ policy)
  let password = Buffer.concat([activationBytes7, rngBytes]);
  if (policy && policy.length > 0) {
    password = Buffer.concat([password, Buffer.from(policy, 'utf-8')]);
    console.log('Debug - Policy added:', Buffer.from(policy, 'utf-8').toString('hex'));
  }

  console.log('Debug - Password:', password.toString('hex'));

  // PBKDF2でキー導出
  const salt = Buffer.from(cleanSerial, 'utf-8');
  const key = crypto.pbkdf2Sync(password, salt, 8, 16, 'sha256');

  console.log('Debug - Salt:', salt.toString('hex'));
  console.log('Debug - Final key:', key.toString('hex'));

  return key;
}/**
 * otpauth URI を生成
 * @param {string} issuer - 発行者名
 * @param {string} accountName - アカウント名
 * @param {Buffer} secretBuffer - OTP シークレット（バッファ）
 * @param {string} algorithm - ハッシュアルゴリズム（例：SHA256）
 * @param {number} digits - OTP の桁数（例：6）
 * @param {number} period - 有効期間（秒単位、例：30）
 * @returns {string} - otpauth URI
 */
function generateOtpauthUri(issuer, accountName, secretBuffer, algorithm = 'SHA256', digits = 6, period = 30) {
  // Base32 エンコード（RFC 4648、パディングなし）
  const secret = base32Encode(secretBuffer, 'RFC4648', { padding: false });

  // ラベルのエンコード（issuer:accountName）
  const label = encodeURIComponent(`${issuer}:${accountName}`);

  // パラメータのエンコード
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm,
    digits: digits.toString(),
    period: period.toString(),
  });

  return `otpauth://totp/${label}?${params.toString()}`;
}

// コマンドライン引数の処理
const args = process.argv.slice(2);

// 環境変数から値を取得
const serial = args[0] || process.env.SERIAL;
const activationCode = args[1] || process.env.ACTIVATION_CODE;
const registrationCode = args[2] || process.env.REGISTRATION_CODE;
const accountName = args[3] || process.env.ACCOUNT_NAME;
const policy = args[4] !== undefined ? args[4] : (process.env.POLICY || '');
const issuer = args[5] || process.env.ISSUER || 'ExampleIssuer';
const algorithm = args[6] || process.env.ALGORITHM || 'SHA256';
const digits = args[7] || process.env.DIGITS || 6;
const period = args[8] || process.env.PERIOD || 30;

if (!serial || !activationCode || !registrationCode || !accountName) {
  console.error('Usage: generate-otpauth-uri.js <serial> <activationCode> <registrationCode> <accountName> [policy] [issuer] [algorithm] [digits] [period]');
  console.error('または、.envファイルに必要な環境変数を設定してください。');
  process.exit(1);
}

const otpSecretBuffer = generateOtpSecret(serial, activationCode, registrationCode, policy);
const otpauthUri = generateOtpauthUri(issuer, accountName, otpSecretBuffer, algorithm, digits, period);

console.log('otpauth URI:', otpauthUri);
