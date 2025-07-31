// ブラウザ用のEntrust IdentityGuard TOTP URI生成ツール
// 🤖 AI Generated Tool / AI生成ツール
// このコードはAIによって生成されました。使用前に動作を十分に確認してください。

/**
 * ハイフンを削除
 * @param {string} input - ハイフン区切りの文字列
 * @returns {string} - ハイフンを削除した文字列
 */
function parseCode(input) {
  return input.replace(/-/g, '');
}

/**
 * 文字列をUTF-8バイト配列に変換
 * @param {string} str - 変換する文字列
 * @returns {Uint8Array} - UTF-8バイト配列
 */
function stringToUtf8Bytes(str) {
  return new TextEncoder().encode(str);
}

/**
 * 数値をBig Endianバイト配列に変換
 * @param {bigint} num - 変換する数値
 * @param {number} byteLength - バイト長
 * @returns {Uint8Array} - バイト配列
 */
function bigIntToBytes(num, byteLength) {
  const bytes = new Uint8Array(byteLength);
  for (let i = byteLength - 1; i >= 0; i--) {
    bytes[i] = Number(num & 0xFFn);
    num = num >> 8n;
  }
  return bytes;
}

/**
 * 数値をBig Endianバイト配列に変換（32bit）
 * @param {number} num - 変換する数値
 * @returns {Uint8Array} - 4バイトの配列
 */
function uint32ToBytes(num) {
  const bytes = new Uint8Array(4);
  bytes[0] = (num >>> 24) & 0xFF;
  bytes[1] = (num >>> 16) & 0xFF;
  bytes[2] = (num >>> 8) & 0xFF;
  bytes[3] = num & 0xFF;
  return bytes;
}

/**
 * バイト配列を連結
 * @param {...Uint8Array} arrays - 連結するバイト配列
 * @returns {Uint8Array} - 連結されたバイト配列
 */
function concatBytes(...arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * PBKDF2-HMAC-SHA256を実装
 * @param {Uint8Array} password - パスワード
 * @param {Uint8Array} salt - ソルト
 * @param {number} iterations - 反復回数
 * @param {number} keyLength - キー長
 * @returns {Promise<Uint8Array>} - 導出されたキー
 */
async function pbkdf2(password, salt, iterations, keyLength) {
  const key = await crypto.subtle.importKey(
    'raw',
    password,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: 'SHA-256'
    },
    key,
    keyLength * 8
  );

  return new Uint8Array(derivedBits);
}

/**
 * Entrust IdentityGuard仕様に準拠したOTPシークレットを生成
 * @param {string} serial - シリアル番号
 * @param {string} activationCode - アクティベーションコード
 * @param {string} registrationCode - 登録コード
 * @param {string} [policy=''] - セキュリティポリシー（通常は空文字列）
 * @returns {Promise<Uint8Array>} - OTPシークレット（16バイト）
 */
async function generateOtpSecret(serial, activationCode, registrationCode, policy = '') {
  // ハイフン除去
  const cleanSerial = parseCode(serial);
  const cleanActivation = parseCode(activationCode);
  const cleanRegistration = parseCode(registrationCode);

  // チェックディジット除去（最後の桁）
  const activationWithoutCheck = cleanActivation.slice(0, -1);
  const registrationWithoutCheck = cleanRegistration.slice(0, -1);

  // アクティベーションコードを7バイトのbig-endianに変換
  const activationNum = BigInt(activationWithoutCheck);
  const activationBytes8 = bigIntToBytes(activationNum, 8);
  const activationBytes7 = activationBytes8.slice(1); // 先頭1バイト除去で7バイト

  // 登録コードを4バイトのbig-endianに変換
  const registrationNum = parseInt(registrationWithoutCheck);
  const registrationBytes = uint32ToBytes(registrationNum);

  // RNGバイト（登録コードの後ろ2バイト）
  const rngBytes = registrationBytes.slice(2, 4);

  // パスワード = activationBytes + rngBytes (+ policy)
  let password = concatBytes(activationBytes7, rngBytes);
  if (policy && policy.length > 0) {
    password = concatBytes(password, stringToUtf8Bytes(policy));
  }

  // PBKDF2でキー導出（Entrust IdentityGuard仕様）
  const salt = stringToUtf8Bytes(cleanSerial);
  const key = await pbkdf2(password, salt, 8, 16);

  return key;
}

/**
 * Base32エンコード（RFC 4648、パディングなし）
 * @param {Uint8Array} data - エンコードするデータ
 * @returns {string} - Base32エンコードされた文字列
 */
function base32Encode(data) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let result = '';
  let bits = 0;
  let value = 0;

  for (let i = 0; i < data.length; i++) {
    value = (value << 8) | data[i];
    bits += 8;

    while (bits >= 5) {
      result += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    result += alphabet[(value << (5 - bits)) & 31];
  }

  return result;
}

/**
 * otpauth URI を生成
 * @param {string} issuer - 発行者名
 * @param {string} accountName - アカウント名
 * @param {Uint8Array} secretBuffer - OTPシークレット（バイト配列）
 * @returns {string} - otpauth URI
 */
function generateOtpauthUri(issuer, accountName, secretBuffer) {
  // Base32エンコード（RFC 4648、パディングなし）
  const secret = base32Encode(secretBuffer);

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

/**
 * 入力値の検証
 * @param {Object} inputs - 入力値オブジェクト
 * @returns {string|null} - エラーメッセージまたはnull
 */
function validateInputs(inputs) {
  const { serial, activationCode, registrationCode, accountName } = inputs;

  if (!serial || !activationCode || !registrationCode || !accountName) {
    return '必要なフィールドが入力されていません。';
  }

  // シリアル番号の形式チェック（数字とハイフンのみ）
  if (!/^[\d-]+$/.test(serial)) {
    return 'シリアル番号は数字とハイフンのみで入力してください。';
  }

  // アクティベーションコードの形式チェック
  if (!/^[\d-]+$/.test(activationCode)) {
    return 'アクティベーションコードは数字とハイフンのみで入力してください。';
  }

  // 登録コードの形式チェック
  if (!/^[\d-]+$/.test(registrationCode)) {
    return '登録コードは数字とハイフンのみで入力してください。';
  }

  // 数値の長さチェック
  const cleanSerial = parseCode(serial);
  const cleanActivation = parseCode(activationCode);
  const cleanRegistration = parseCode(registrationCode);

  if (cleanSerial.length < 5 || cleanSerial.length > 20) {
    return 'シリアル番号の桁数が正しくありません。';
  }

  if (cleanActivation.length < 10 || cleanActivation.length > 20) {
    return 'アクティベーションコードの桁数が正しくありません。';
  }

  if (cleanRegistration.length < 5 || cleanRegistration.length > 15) {
    return '登録コードの桁数が正しくありません。';
  }

  return null;
}

/**
 * エラーメッセージを表示
 * @param {string} message - エラーメッセージ
 */
function showError(message) {
  const errorSection = document.getElementById('errorSection');
  const errorMessage = document.getElementById('errorMessage');
  const resultSection = document.getElementById('resultSection');

  errorMessage.textContent = message;
  errorSection.classList.add('show');
  resultSection.classList.remove('show');
}

/**
 * エラーメッセージを非表示
 */
function hideError() {
  const errorSection = document.getElementById('errorSection');
  errorSection.classList.remove('show');
}

/**
 * 結果を表示
 * @param {string} uri - 生成されたURI
 */
function showResult(uri) {
  const resultSection = document.getElementById('resultSection');
  const uriOutput = document.getElementById('uriOutput');

  uriOutput.textContent = uri;
  resultSection.classList.add('show');
  hideError();
}

/**
 * クリップボードにコピー
 * @param {string} text - コピーするテキスト
 */
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);

    // コピー成功のフィードバック
    const copyBtn = document.getElementById('copyBtn');
    const originalText = copyBtn.textContent;
    copyBtn.textContent = '✅ コピーしました！';
    copyBtn.style.background = '#27ae60';

    setTimeout(() => {
      copyBtn.textContent = originalText;
      copyBtn.style.background = '#27ae60';
    }, 2000);
  } catch (err) {
    alert('コピーに失敗しました。URIを手動で選択してコピーしてください。');
  }
}

/**
 * QRコードを生成・表示
 * @param {string} uri - QRコードにするURI
 */
function showQRCode(uri) {
  const qrCodeSection = document.getElementById('qrCode');
  const canvas = document.getElementById('qrCanvas');

  // QRコードを生成
  const qrCodeDivId = 'qrCanvas';
  // 既存のQRコードをクリア
  const qrCanvas = document.getElementById(qrCodeDivId);
  if (qrCanvas) {
    qrCanvas.innerHTML = '';
  }
  try {
    // QRCodejsはcanvasではなくdiv要素に描画する
    new QRCode(qrCodeDivId, {
      text: uri,
      width: 256,
      height: 256,
      colorDark: '#000000',
      colorLight: '#ffffff',
      correctLevel: QRCode.CorrectLevel.H
    });
    qrCodeSection.style.display = 'block';
  } catch (error) {
    console.error('QRコード生成エラー:', error);
    alert('QRコードの生成に失敗しました。');
  }
}

/**
 * フォーム送信のハンドラ
 * @param {Event} event - フォーム送信イベント
 */
async function handleFormSubmit(event) {
  event.preventDefault();

  const formData = new FormData(event.target);
  const inputs = {
    serial: formData.get('serial').trim(),
    activationCode: formData.get('activationCode').trim(),
    registrationCode: formData.get('registrationCode').trim(),
    accountName: formData.get('accountName').trim(),
    issuer: formData.get('issuer').trim() || 'Entrust'
  };

  // 入力値の検証
  const validationError = validateInputs(inputs);
  if (validationError) {
    showError(validationError);
    return;
  }

  try {
    // ボタンを無効化
    const submitBtn = document.querySelector('.generate-btn');
    submitBtn.disabled = true;
    submitBtn.textContent = '生成中...';

    // OTPシークレットを生成
    const otpSecret = await generateOtpSecret(
      inputs.serial,
      inputs.activationCode,
      inputs.registrationCode
    );

    // otpauth URIを生成
    const otpauthUri = generateOtpauthUri(
      inputs.issuer,
      inputs.accountName,
      otpSecret
    );

    // 結果を表示
    showResult(otpauthUri);

    // QRコードセクションを非表示にリセット
    document.getElementById('qrCode').style.display = 'none';

  } catch (error) {
    console.error('TOTP URI生成エラー:', error);
    showError('TOTP URIの生成中にエラーが発生しました: ' + error.message);
  } finally {
    // ボタンを有効化
    const submitBtn = document.querySelector('.generate-btn');
    submitBtn.disabled = false;
    submitBtn.textContent = 'TOTP URI を生成';
  }
}

// DOM読み込み完了後の初期化
document.addEventListener('DOMContentLoaded', function () {
  // フォーム送信イベントリスナー
  const form = document.getElementById('totpForm');
  form.addEventListener('submit', handleFormSubmit);

  // コピーボタンのイベントリスナー
  const copyBtn = document.getElementById('copyBtn');
  copyBtn.addEventListener('click', function () {
    const uri = document.getElementById('uriOutput').textContent;
    copyToClipboard(uri);
  });

  // QRコードボタンのイベントリスナー
  const qrBtn = document.getElementById('qrBtn');
  qrBtn.addEventListener('click', function () {
    const uri = document.getElementById('uriOutput').textContent;
    showQRCode(uri);
  });

  // 入力フィールドのリアルタイム検証
  const requiredFields = document.querySelectorAll('.required');
  requiredFields.forEach(field => {
    field.addEventListener('input', function () {
      if (this.value.trim()) {
        this.style.borderLeftColor = '#27ae60';
      } else {
        this.style.borderLeftColor = '#e74c3c';
      }
    });
  });

  console.log('Entrust IdentityGuard TOTP URI生成ツール が初期化されました');
  console.log('すべての処理はクライアントサイドで実行され、データは外部に送信されません');
});
