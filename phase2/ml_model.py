import kagglehub
import pandas as pd
import os
import urllib.parse
import re
import joblib
import numpy as np

from scipy.sparse import hstack

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

path = kagglehub.dataset_download("sajid576/sql-injection-dataset")

file_path = os.path.join(path, "Modified_SQL_Dataset.csv")
data = pd.read_csv(file_path)


def normalize(text):
    text = urllib.parse.unquote(text)
    text = text.lower()
    text = re.sub(r"([=()'\";,/])", r" \1 ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_features(text):
    text = text.lower()

    return np.array([
        text.count("'"),
        text.count('"'),
        text.count("--"),
        text.count("/*"),
        text.count("*/"),
        text.count(" or "),
        text.count(" and "),
        text.count("union"),
        text.count("select"),
        text.count("sleep"),
        len(text),
        int(" or " in text),
        int("union" in text),
        int("select" in text),
        int("information_schema" in text),
    ])


data = data.rename(columns={
    "Query": "text",
    "Label": "label"
})

data = data.dropna()
data["text"] = data["text"].astype(str)
data["text"] = data["text"].apply(normalize)

X = data["text"]
y = data["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

vectorizer = TfidfVectorizer(
    max_features=5000,
    ngram_range=(1, 2)
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

X_train_feat = np.array([extract_features(t) for t in X_train])
X_test_feat = np.array([extract_features(t) for t in X_test])

X_train_final = hstack([X_train_vec, X_train_feat])
X_test_final = hstack([X_test_vec, X_test_feat])

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42
)

model.fit(X_train_final, y_train)

y_pred = model.predict(X_test_final)

print(classification_report(y_test, y_pred))

joblib.dump(model, "sqli_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")


def predict(text):
    text_n = normalize(text)

    vec = vectorizer.transform([text_n])
    feat = extract_features(text_n).reshape(1, -1)

    final = hstack([vec, feat])

    pred = model.predict(final)[0]
    proba = model.predict_proba(final)[0][1]

    return pred, proba


tests = [
    "/login?user=admin' OR 1=1--",
    "/api/user?id=5",
    "hello world",
    "' oR/**/1=1--",
    "/api?id=1%20UNIoN%20SELect%201,2,3",
    "/product?id=1 UNION SELECT password",
    "{\"email\":\"test@mail.com\"}",
    "{\"email\":\"select@mail.com\"}"
]

for t in tests:
    pred, proba = predict(t)
    print(t, "=>", pred, "confidence:", round(proba, 3))