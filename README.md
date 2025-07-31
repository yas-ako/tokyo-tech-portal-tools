# Entrust IdentityGuard TOTP認証URI生成ツール

Entrust IdentityGuardのソフトトークンから、Google AuthenticatorやAuthy等で使用可能なTOTP（Time-based One-Time Password）認証URIを生成するツールです。

## 特徴

- Entrust IdentityGuardの公式仕様に準拠
- PBKDF2キー導出関数を使用したセキュアな実装
- **Webブラウザ版**と**コマンドライン版**の両方を提供
- すべての処理がクライアントサイドで実行（Webブラウザ版）
- Google Authenticator、Authy等の主要TOTPアプリで動作確認済み

## 使用方法

### 🌐 Webブラウザ版（推奨）

1. `index.html`をWebブラウザで開く：
```bash
# ローカルファイルとして開く
open index.html
# または
firefox index.html
# または
chrome index.html
```

2. フォームに必要な情報を入力：
   - シリアル番号
   - アクティベーションコード
   - 登録コード
   - アカウント名
   - 発行者名（オプション）

3. 「TOTP URI を生成」ボタンをクリック

4. 生成されたURIをコピーまたはQRコードでスキャン

**特徴:**
- ✅ サーバーに一切データを送信しない
- ✅ すべての処理がブラウザ内で完結
- ✅ QRコード生成機能付き
- ✅ レスポンシブデザイン対応

### 💻 コマンドライン版

#### インストール

##### 前提条件

- Node.js 14.0.0以上
- npm

##### セットアップ

1. リポジトリをクローン：
```bash
git clone <repository-url>
cd tokyo-tech-portal-tools
```

2. 依存関係をインストール：
```bash
npm install
```

3. 環境変数ファイルを設定（オプション）：
```bash
cp env.example.txt .env
# .envファイルを編集して実際の値を設定
```

#### 使用方法

##### コマンドライン引数での実行

```bash
node entrust-totp.js <serial> <activationCode> <registrationCode> <accountName> [issuer]
```

###### 例：
```bash
node entrust-totp.js 12345-67890 1234-5678-9012-3456 98765-43210 user@example.com "MyCompany"
```

##### 環境変数での実行

1. `.env`ファイルに必要な情報を設定：

```env
SERIAL=12345-67890
ACTIVATION_CODE=1234-5678-9012-3456
REGISTRATION_CODE=98765-43210
ACCOUNT_NAME=user@example.com
ISSUER=MyCompany
```

2. 設定ファイルを使用して実行：

```bash
node entrust-totp.js
```

## パラメータ

| パラメータ | 必須 | 説明 | 例 |
|-----------|------|------|-----|
| serial | ✓ | シリアル番号 | `12345-67890` |
| activationCode | ✓ | アクティベーションコード | `1234-5678-9012-3456` |
| registrationCode | ✓ | 登録コード | `98765-43210` |
| accountName | ✓ | アカウント名 | `user@example.com` |
| issuer | - | 発行者名（デフォルト: "Entrust"） | `MyCompany` |

## 出力例

```
TOTP認証URI が正常に生成されました:

otpauth://totp/MyCompany%3Auser%40example.com?secret=ABCD1234EFGH5678IJKL9012&issuer=MyCompany&algorithm=SHA256&digits=6&period=30

このURIをGoogle AuthenticatorやAuthy等のTOTPアプリに追加してください。
```

## TOTPアプリでの設定

1. 生成されたURIをコピー
2. Google Authenticator、Authy等のTOTPアプリを開く
3. 「アカウントを追加」または「QRコードをスキャン」を選択
4. 「手動で入力」を選択してURIを貼り付け、または表示されるQRコードをスキャン

## セキュリティ上の注意事項

⚠️ **重要**: このツールは機密情報を扱います。以下の点にご注意ください：

- `.env`ファイルには実際の認証情報が含まれるため、**絶対にGitリポジトリにコミットしないでください**
- `.env`ファイルは適切なファイル権限（600等）を設定してください
- 不要になった`.env`ファイルや出力されたURIは安全に削除してください
- 本ツールは個人使用または組織内での使用を想定しています

## ライセンス

MIT License

## トラブルシューティング

### よくある問題

1. **「必要なパラメータが不足しています」エラー**
   - すべての必須パラメータが正しく設定されているか確認してください
   - ハイフンも含めて正確に入力してください

2. **「TOTP URI の生成に失敗しました」エラー**
   - 入力されたコードが正しい形式か確認してください
   - 数値以外の文字が含まれていないか確認してください

3. **TOTPアプリで認証が失敗する**
   - デバイスの時刻が正確に設定されているか確認してください
   - 生成されたURIが正しくアプリに追加されているか確認してください
