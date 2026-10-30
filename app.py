import os
import re
import hmac

from flask import Flask, request
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

app = Flask(__name__)


def page(title, message, status=200):
    html = f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
body {{
    margin: 0;
    padding: 24px;
    background: #f4f6f8;
    color: #1f2937;
    font-family: sans-serif;
    line-height: 1.8;
}}
main {{
    max-width: 480px;
    margin: 60px auto;
    padding: 28px;
    background: white;
    border-radius: 16px;
}}
h1 {{ font-size: 24px; }}
p {{ font-size: 16px; }}
</style>
</head>
<body>
<main>
<h1>{title}</h1>
<p>{message}</p>
</main>
</body>
</html>"""
    return html, status


@app.after_request
def prevent_cache(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def load_key(name):
    value = os.environ.get(name, "")
    if not re.fullmatch(r"[0-9a-fA-F]{32}", value):
        raise ValueError("Invalid key configuration")
    return bytes.fromhex(value)


def calculate_mac(key, data):
    obj = CMAC.new(key, ciphermod=AES)
    obj.update(data)
    return obj.digest()


def verify_sdm(picc_data, signature, meta_key, read_key):
    # 対応方式：
    # AES、暗号化UID＋カウンター、追加暗号化ファイルなし。
    # タグのSDMMACInputOffsetとSDMMACOffsetは同じ値に設定。
    raw = AES.new(
        meta_key, AES.MODE_CBC, iv=bytes(16)
    ).decrypt(picc_data)

    if raw[0] != 0xC7:
        raise ValueError("Unsupported data or incorrect key")

    uid = raw[1:8]
    counter_bytes = raw[8:11]

    session_key = calculate_mac(
        read_key,
        bytes.fromhex("3CC300010080") + uid + counter_bytes
    )
    expected = calculate_mac(session_key, b"")[1::2]

    if not hmac.compare_digest(expected, signature):
        raise ValueError("Invalid authentication code")

    return uid.hex().upper(), int.from_bytes(counter_bytes, "little")


@app.route("/")
def home():
    try:
        load_key("SDM_META_READ_KEY")
        load_key("SDM_FILE_READ_KEY")
    except ValueError:
        return page(
            "秘密鍵の設定を確認してください",
            "RenderのEnvironmentで、2つの秘密鍵の名前と"
            "32文字の16進数になっているかを確認してください。",
            503
        )

    return page(
        "NFC真贋判定デモ",
        "暗号検証プログラムを読み込みました。"
        "<br>秘密鍵2項目の形式は正常です。"
        "<br>次は自己テストを実行してください。"
        '<br><a href="/self-test">自己テストを実行</a>'
    )


@app.route("/self-test")
def self_test():
    # 公開されたテスト専用データ。実際の秘密鍵は使いません。
    data = bytes.fromhex("EF963FF7828658A599F3041510671E88")
    signature = bytes.fromhex("94EED9EE65337086")

    try:
        result = verify_sdm(data, signature, bytes(16), bytes(16))
        if result != ("04DE5F1EACC040", 61):
            raise ValueError("Unexpected result")

        try:
            verify_sdm(data, bytes(8), bytes(16), bytes(16))
        except ValueError:
            pass
        else:
            raise ValueError("Invalid data accepted")

    except ValueError:
        return page(
            "自己テスト失敗",
            "暗号処理を確認する必要があります。",
            500
        )

    return page(
        "暗号処理の自己テスト成功",
        "公開サンプルの検証に成功しました。"
        "<br>不正な認証コードを拒否することも確認しました。"
        "<br>実際のタグと秘密鍵の一致確認は、タグ設定後に行います。"
    )


@app.route("/verify")
def verify():
    if not request.args:
        return page(
            "NFCタグから読み取ってください",
            "認証受付ページは動作しています。"
            "<br>タグの認証データがまだ送られていません。",
            400
        )

    if (
        set(request.args) != {"picc_data", "cmac"}
        or any(len(request.args.getlist(k)) != 1 for k in request.args)
    ):
        return page("認証できません", "URLの形式が正しくありません。", 400)

    data = request.args["picc_data"]
    signature = request.args["cmac"]

    if (
        not re.fullmatch(r"[0-9a-fA-F]{32}", data)
        or not re.fullmatch(r"[0-9a-fA-F]{16}", signature)
    ):
        return page("認証できません", "認証データの形式が正しくありません。", 400)

    try:
        meta_key = load_key("SDM_META_READ_KEY")
        read_key = load_key("SDM_FILE_READ_KEY")
    except ValueError:
        return page("設定が未完了です", "サーバーの秘密鍵設定を確認してください。", 503)

    try:
        verify_sdm(
            bytes.fromhex(data),
            bytes.fromhex(signature),
            meta_key,
            read_key
        )
    except ValueError:
        return page(
            "暗号が一致しません",
            "タグの設定と秘密鍵、または認証データを確認してください。",
            403
        )

    return page(
        "暗号の一致を確認しました",
        "設定した秘密鍵による検証に成功しました。"
        "<br>URLの再利用検出はまだ未実装です。"
        "<br>現段階では、最終的な真贋判定は行いません。"
    )
@app.route("/db-check")
def db_check():
    import psycopg

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        return page(
            "接続先が未設定です",
            "RenderのEnvironmentにDATABASE_URLを登録してください。",
            503
        )

    try:
        with psycopg.connect(
            database_url,
            connect_timeout=5,
            sslmode="require",
            options="-c statement_timeout=5000"
        ) as conn:
            result = conn.execute("SELECT 1").fetchone()

        if result != (1,):
            return page("接続確認に失敗しました", "設定を確認してください。", 503)

    except psycopg.Error:
        return page(
            "データベースに接続できません",
            "DATABASE_URL、データベースの稼働状態、"
            "Webサーバーと同じRegionかを確認してください。",
            503
        )

    return page(
        "データベース接続成功",
        "Webサーバーからデータベースへの接続を確認しました。"
        "<br>読み取り履歴の保存処理は、次に追加します。"
    )
