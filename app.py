from flask import Flask

app = Flask(__name__)


def page(title, message):
    return f"""<!DOCTYPE html>
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


@app.route("/")
def home():
    return page(
        "NFC真贋判定デモ",
        "Webサーバーは正常に動作しています。"
        "<br>現在、NFCタグの暗号認証機能を準備中です。"
    )


@app.route("/verify")
def verify():
    return page(
        "認証機能の準備中",
        "認証受付ページに接続できました。"
        "<br>現時点では、タグの真贋判定は行っていません。"
    ), 503
