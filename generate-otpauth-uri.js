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
 * // SERIAL=48244-13456
 * // ACTIVATION_CODE=1745-7712-6942-8698
 * // REGISTRATION_CODE=12211-49352
 * // ACCOUNT_NAME=alice@example.com
 * // POLICY={"allowUnsecured":"false","trustedExecution":"NOT_ALLOWED"}
 * // ISSUER=ExampleCorp
 * // ALGORITHM=SHA256
 * // DIGITS=6
 * // PERIOD=30
 * 
 * @param {string} serial - シリアル番号（例：48244-13456）
 * @param {string} activationCode - アクティベーションコード（例：1745-7712-6942-8698）
 * @param {string} registrationCode - 登録コード（例：12211-49352）
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
 * OTP シークレットを生成
 * @param {string} serial - シリアル番号
 * @param {string} activationCode - アクティベーションコード
 * @param {string} registrationCode - 登録コード
 * @param {string} [policy] - ポリシー（オプション）
 * @returns {Buffer} - OTP シークレット（バッファ）
 */
function generateOtpSecret(serial, activationCode, registrationCode, policy = '') {
  // それぞれハイフン除去→バッファ化
  const serialBuf = Buffer.from(parseCode(serial));
  const activationBuf = Buffer.from(parseCode(activationCode));
  const registrationBuf = Buffer.from(parseCode(registrationCode));
  // バッファ連結
  const data = Buffer.concat([serialBuf, activationBuf, registrationBuf]);
  // SHA-256
  const hash = crypto.createHash('sha256').update(data).digest();
  return hash.subarray(0, 16);
}

/**
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
const policy = args[4] || process.env.POLICY || '';
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
