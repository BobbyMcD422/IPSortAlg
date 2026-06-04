from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

NORMAL_LABEL = "normal"


def split_ip_column(rows):
    features = rows.copy()

    if "IP" in features.columns:
        host_and_port = features["IP"].astype(str).str.extract(
            r"^(?P<host>.*?)(?::(?P<port>\d+))?$"
        )
        features["host"] = host_and_port["host"]
        features["port"] = pd.to_numeric(host_and_port["port"], errors="coerce").fillna(0)
        features = features.drop(columns=["IP"])

    return features


def add_behavior_features(rows):
    features = split_ip_column(rows)

    if "time" not in features.columns or "host" not in features.columns:
        return features

    features["_original_order"] = range(len(features))
    features["time"] = pd.to_numeric(features["time"], errors="coerce").fillna(0)
    features = features.sort_values("time").reset_index(drop=True)

    features["time_since_previous_event"] = features["time"].diff().fillna(0)
    features["events_from_same_host_so_far"] = features.groupby("host").cumcount() + 1
    features["time_since_previous_same_host"] = (
        features.groupby("host")["time"].diff().fillna(0)
    )

    for window in (1, 5, 30):
        features[f"events_from_same_host_last_{window}_sec"] = features.apply(
            lambda row: count_host_events_in_window(features, row, window),
            axis=1,
        )

    features["host_events_seen_before"] = features.groupby("host").cumcount()
    features["port_events_seen_before"] = features.groupby("port").cumcount()
    features["is_ip_address"] = features["host"].str.match(r"^\d{1,3}(\.\d{1,3}){3}$").astype(int)
    features["is_hostname"] = 1 - features["is_ip_address"]

    features = features.sort_values("_original_order").drop(columns=["_original_order"])
    features = features.drop(columns=["host", "time"])
    return features


def count_host_events_in_window(features, row, window_seconds):
    same_host = features["host"] == row["host"]
    in_window = features["time"].between(row["time"] - window_seconds, row["time"])
    return int((same_host & in_window).sum())


def prepare_features(rows):
    features = add_behavior_features(rows)

    for column in features.columns:
        try:
            features[column] = pd.to_numeric(features[column])
        except ValueError:
            pass

    return pd.get_dummies(features)


def train_model(
    data_file,
    target_column="Source",
    model_file="models/attack_detector.joblib",
    features_file="data/engineered_features.csv",
):
    data_file = Path(data_file)
    model_file = Path(model_file)
    features_file = Path(features_file)

    df = pd.read_csv(data_file)

    if target_column not in df.columns:
        raise ValueError(f"Expected a target column named '{target_column}' in {data_file}")

    df[target_column] = df[target_column].fillna("").astype(str).str.strip()
    df.loc[df[target_column] == "", target_column] = NORMAL_LABEL

    X = prepare_features(df.drop(columns=[target_column]))
    y = df[target_column]

    feature_export = X.copy()
    feature_export[target_column] = y
    features_file.parent.mkdir(parents=True, exist_ok=True)
    feature_export.to_csv(features_file, index=False)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=5,
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_train, y_train)

    model_file.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "columns": X.columns.tolist(),
            "target_column": target_column,
        },
        model_file,
    )

    predictions = model.predict(X_test)
    labels = sorted(y.unique())
    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, average="weighted", zero_division=0)
    recall = recall_score(y_test, predictions, average="weighted", zero_division=0)
    f1 = f1_score(y_test, predictions, average="weighted", zero_division=0)
    matrix = confusion_matrix(y_test, predictions, labels=labels)
    report = classification_report(y_test, predictions)

    return {
        "data_file": data_file,
        "model_file": model_file,
        "features_file": features_file,
        "rows_trained": len(X_train),
        "rows_tested": len(X_test),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion_matrix": matrix,
        "confusion_matrix_labels": labels,
        "report": report,
        "target_column": target_column,
    }


def predict_file(
    data_file,
    model_file="models/attack_detector.joblib",
    output_file="data/predictions.csv",
    target_column=None,
):
    data_file = Path(data_file)
    model_file = Path(model_file)
    output_file = Path(output_file)

    bundle = joblib.load(model_file)
    model = bundle["model"]
    columns = bundle["columns"]
    target_column = target_column or bundle.get("target_column", "Source")

    df = pd.read_csv(data_file)
    feature_rows = df.drop(columns=[target_column], errors="ignore")
    X = prepare_features(feature_rows)
    X = X.reindex(columns=columns, fill_value=0)

    predictions = model.predict(X)
    prediction_probabilities = model.predict_proba(X).max(axis=1)

    results = df.copy()
    results[target_column] = predictions
    results["prediction_confidence"] = prediction_probabilities

    output_file.parent.mkdir(parents=True, exist_ok=True)
    results.to_csv(output_file, index=False)

    return {
        "data_file": data_file,
        "model_file": model_file,
        "output_file": output_file,
        "rows_predicted": len(results),
        "results": results,
        "target_column": target_column,
    }
