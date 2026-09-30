import json
from pathlib import Path


def load_dataset(path: str = "experiments/dataset.json") -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def evaluate_baseline(path: str = "experiments/dataset.json") -> dict:
    """Simple keyword baseline used as a comparison reference."""
    dataset = load_dataset(path)
    keywords = ("sql injection", "failed login", "malware", "ransomware")
    tp = fp = tn = fn = 0

    for item in dataset:
        detected = any(k in item["message"].lower() for k in keywords)
        malicious = item["label"] == "malicious"
        if detected and malicious: tp += 1
        elif detected: fp += 1
        elif malicious: fn += 1
        else: tn += 1

    total = len(dataset)
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "method": "keyword-baseline",
        "dataset_size": total,
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }
