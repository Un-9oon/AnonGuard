#!/usr/bin/env python3
"""
Empirical Website Fingerprinting (WF) Classifier Evaluation Script for AnonGuard.

Evaluates Machine Learning classifier accuracy on:
1. Raw Un-morphed traffic flow dataset.
2. RMT Wigner-Surmise morphed traffic flow dataset.

Outputs accuracy, precision, recall, F1-score, and accuracy degradation ratio.
"""

import sys
import os
import csv
import math
from collections import Counter, defaultdict

def load_dataset(csv_path):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset file not found: {csv_path}")
    X, y = [], []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            if not row:
                continue
            y.append(int(row[0]))
            X.append([float(val) for val in row[1:]])
    return X, y

class KNearestNeighborsClassifier:
    """Pure Python k-NN classifier for zero-dependency empirical evaluation."""
    def __init__(self, k=3):
        self.k = k
        self.X_train = []
        self.y_train = []

    fn_euclidean = lambda self, a, b: math.sqrt(sum((x - y)**2 for x, y in zip(a, b)))

    def fit(self, X, y):
        self.X_train = X
        self.y_train = y

    def predict(self, X_test):
        predictions = []
        for x_t in X_test:
            distances = [(self.fn_euclidean(x_t, x_tr), label) for x_tr, label in zip(self.X_train, self.y_train)]
            distances.sort(key=lambda item: item[0])
            top_k_labels = [label for _, label in distances[:self.k]]
            most_common = Counter(top_k_labels).most_common(1)[0][0]
            predictions.append(most_common)
        return predictions

def train_test_split(X, y, test_ratio=0.3, seed=42):
    import random
    combined = list(zip(X, y))
    random.seed(seed)
    random.shuffle(combined)
    split_idx = int(len(combined) * (1 - test_ratio))
    train_data = combined[:split_idx]
    test_data = combined[split_idx:]
    X_train, y_train = zip(*train_data)
    X_test, y_test = zip(*test_data)
    return list(X_train), list(y_train), list(X_test), list(y_test)

def evaluate_metrics(y_true, y_pred):
    correct = sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp)
    total = len(y_true)
    accuracy = correct / total if total > 0 else 0.0

    classes = sorted(list(set(y_true)))
    precisions, recalls, f1s = [], [], []

    for c in classes:
        tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == c and yp == c)
        fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt != c and yp == c)
        fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == c and yp != c)

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

        precisions.append(prec)
        recalls.append(rec)
        f1s.append(f1)

    macro_prec = sum(precisions) / len(precisions) if precisions else 0.0
    macro_rec = sum(recalls) / len(recalls) if recalls else 0.0
    macro_f1 = sum(f1s) / len(f1s) if f1s else 0.0

    return {
        "accuracy": accuracy,
        "precision": macro_prec,
        "recall": macro_rec,
        "f1_score": macro_f1
    }

def evaluate_dataset(csv_path):
    X, y = load_dataset(csv_path)
    X_tr, y_tr, X_te, y_te = train_test_split(X, y, test_ratio=0.3, seed=42)
    clf = KNearestNeighborsClassifier(k=3)
    clf.fit(X_tr, y_tr)
    y_pred = clf.predict(X_te)
    return evaluate_metrics(y_te, y_pred)

def main():
    raw_csv = sys.argv[1] if len(sys.argv) > 1 else "target/eval_data/raw_unmorphed.csv"
    morphed_csv = sys.argv[2] if len(sys.argv) > 2 else "target/eval_data/rmt_morphed.csv"

    print("=== Empirical Traffic-Morphing Classifier Evaluation ===")
    print(f"Raw Dataset: {raw_csv}")
    print(f"Morphed Dataset: {morphed_csv}\n")

    raw_metrics = evaluate_dataset(raw_csv)
    morphed_metrics = evaluate_dataset(morphed_csv)

    print("=== Evaluation Results ===")
    print(f"Raw Traffic Classifier Accuracy:  {raw_metrics['accuracy']*100:.2f}% (F1: {raw_metrics['f1_score']:.4f})")
    print(f"Morphed Traffic Classifier Accuracy: {morphed_metrics['accuracy']*100:.2f}% (F1: {morphed_metrics['f1_score']:.4f})")
    print(f"Accuracy Collapse Ratio:          {((raw_metrics['accuracy'] - morphed_metrics['accuracy'])/raw_metrics['accuracy'])*100:.2f}%\n")

    # Anti-hollow assertions
    assert raw_metrics['accuracy'] > 0.80, f"Raw traffic accuracy must be high (>80%), got {raw_metrics['accuracy']}"
    assert morphed_metrics['accuracy'] < 0.45, f"Morphed traffic accuracy must collapse (<45%), got {morphed_metrics['accuracy']}"

    print("[SUCCESS] Anti-hollow traffic-morphing evaluation passed!")

if __name__ == "__main__":
    main()
