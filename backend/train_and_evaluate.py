import numpy
import torch
from tqdm import tqdm
import json
from sklearn.svm import SVC
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from imblearn.over_sampling import SMOTE
import joblib
from sklearn.metrics import (
    confusion_matrix, classification_report,
    roc_auc_score, average_precision_score,
    multilabel_confusion_matrix,
)
from sklearn.preprocessing import label_binarize
import torch.nn.functional as F
import matplotlib.pyplot as plt
import seaborn as sns


##################### Tested on python 3.12 and 3.9 !

def train_and_evaluate(dataset_csv_path):
    """ Phase 0 """

    ### 0.1: GPU Usage ###
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using {device}")

    ### 0.2: Data Size ###
    data_size = 500000

    """ Phase 1 Data Import and Preprocessing """
    ### 1.1: Data Import, Severity Map ###
    df = pd.read_csv(dataset_csv_path, skiprows=range(1, 90000), nrows=data_size)
    #df = pd.read_csv("C:/Users/Daniel/PycharmProjects/Final_Proj_Anoseek/datasets/NF-UNSW-NB15-v2_50000.csv")
    print(df['Attack'].unique().shape)
    # now we'll remove the unwanted features which aren't numerical
    cols_to_drop = [
        "IPV4_SRC_ADDR", "IPV4_DST_ADDR",
        "L4_SRC_PORT", "L4_DST_PORT",
        "IN_PKTS", "OUT_PKTS",
        "TCP_FLAGS", "CLIENT_TCP_FLAGS",
        "MAX_TTL", "ICMP_TYPE",
        "RETRANSMITTED_IN_PKTS", "RETRANSMITTED_OUT_PKTS",
        "DNS_TTL_ANSWER", "FTP_COMMAND_RET_CODE",
        "Label",
    ]
    df = df.drop(columns=cols_to_drop, errors='ignore')
    print(df.info())
    # convertion of Attack severity to numbers
    severity_dict = {
        "Benign": 0,

        # Recon / scanning
        "Infilteration": 1,
        "Bot": 1,

        # Brute force attacks
        "SSH-Bruteforce": 2,
        "FTP-BruteForce": 2,
        "Brute Force -Web": 2,

        # DoS / DDoS attacks
        "DoS attacks-Slowloris": 3,
        "DoS attacks-Hulk": 3,
        "DoS attacks-GoldenEye": 3,
        "DoS attacks-SlowHTTPTest": 3,
        "DDoS attacks-LOIC-HTTP": 3,
        "DDOS attack-HOIC": 3,
        "DDOS attack-LOIC-UDP": 3,

        # High severity / exploitation attacks
        "SQL Injection": 4,
        "Brute Force -XSS": 4
    }
    feature_cols = df.columns
    df['Attack'] = df['Attack'].map(severity_dict)

    X_df = df.iloc[:, :-1].copy()  # all rows of all features without the label and attack type
    # Replace infinity with NaN
    X_df = X_df.replace([np.inf, -np.inf], np.nan)
    y_arr = df.iloc[:, -1:].values  # all rows of attack type (severity)

    # Split FIRST so test data doesn't leak into our train-time statistics
    X_train_df, X_test_df, y_train_arr, y_test_arr = train_test_split(
        X_df, y_arr, test_size=0.2, random_state=42, stratify=y_arr
    )

    # Compute medians and clip bounds on TRAIN ONLY
    medians = X_train_df.median(numeric_only=True)
    lower = X_train_df.quantile(0.001, numeric_only=True)
    upper = X_train_df.quantile(0.999, numeric_only=True)

    # Apply identical preprocessing to both splits
    X_train_df = X_train_df.fillna(medians).clip(lower=lower, upper=upper, axis=1)
    X_test_df = X_test_df.fillna(medians).clip(lower=lower, upper=upper, axis=1)

    # Convert to tensors
    X_train = torch.from_numpy(X_train_df.values).float()
    X_test = torch.from_numpy(X_test_df.values).float()
    y_train_tensor = torch.tensor(y_train_arr, dtype=torch.long)
    y_test = torch.tensor(y_test_arr, dtype=torch.long)

    print(X_train.shape, X_test.shape)

    ### 1.2: Feature Scaling ###
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_train_scaled_tensor = torch.from_numpy(X_train_scaled).float()
    smote = SMOTE(random_state=42, k_neighbors=1)
    X_resampled_np, y_resampled_np = smote.fit_resample(X_train_scaled_tensor, y_train_tensor)
    # Convert resampled data back to tensors
    X_resampled_tensor = torch.from_numpy(X_resampled_np).float()
    y_resampled_tensor = torch.from_numpy(y_resampled_np).long()

    X_train_tensor = X_resampled_tensor
    y_train_tensor = y_resampled_tensor

    input_size = X_train_scaled_tensor.shape[1]  # num of features
    print(input_size)

    """ Phase 2 Model Architecture Design """

    ### 2.1: Class Model ###
    class Embeddings(nn.Module):
        def __init__(self, inp_size, embedding_dim, num_classes):
            super().__init__()
            self.feature_extractor = nn.Sequential(
                nn.Linear(inp_size, 15),
                nn.ReLU(),
                nn.Linear(15, 7),
                nn.ReLU(),
                nn.Linear(7, embedding_dim),
                nn.ReLU()
                )

            self.classifier = nn.Linear(
                embedding_dim,
                num_classes
            )

        def forward(self, x):
            embedding = self.feature_extractor(x)
            logits = self.classifier(embedding)
            return logits

        def extract_embeddings(self, x):
            return self.feature_extractor(x)

    """ Phase 2 Replacement Model Architecture Design """

    """ Phase 3: Dataset, DataLoader, and training loop """

    ### 3.1: Variables ###

    embeddings_model = Embeddings(input_size, 16, 5).to(device)
    svc_model = SVC(kernel='rbf', C=0.5, decision_function_shape='ovr')

    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(embeddings_model.parameters(), lr=1e-03, weight_decay=1e-05)

    batch_size = 64
    num_epochs = 15

    ### 3.2: Create DataLoader for batched training ###

    dataset = TensorDataset(
        X_train_tensor,
        y_train_tensor
    )
    train_loader = DataLoader(
        dataset,
        batch_size=64,
        shuffle=True
    )

    extract_loader = DataLoader(
        dataset,
        batch_size=64,
        shuffle=False
    )

    ### 3.2 Training loop ###

    for epoch in range(num_epochs):
        embeddings_model.train()
        running_loss = 0.0

        # Wrap the train_loader with tqdm for a visual progress bar
        progress_bar = tqdm(
            train_loader,
            desc=f"Epoch {epoch + 1}/{num_epochs}",
            unit="batch"
        )

        for (batch, targets) in progress_bar:  # each batch is a tuple from TensorDataset
            batch = batch.to(device)
            targets = targets.view(-1).long().to(device)
            # forward
            logits = embeddings_model(batch)
            # loss
            loss = criterion(logits, targets)
            """
            targets:
            [3, 0, 1, 4]
            
            logits:
            [
             [1.2, 0.3, 0.5, 5.9, 0.1],   ← predicts class 3 ✓
             [0.1, 4.8, 0.2, 0.1, 0.0],   ← predicts class 1 ✗
             [0.3, 3.1, 0.8, 0.1, 0.0],   ← predicts class 1 ✓
             [0.2, 0.1, 0.3, 0.2, 6.0]    ← predicts class 4 ✓
            ]
            """
            # backward
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            # Update running statistics for the bar display
            running_loss += loss.item()
            progress_bar.set_postfix({"Loss": f"{loss.item():.4f}"})

    embeddings_model.eval()
    embeddings = []
    labels = []
    with torch.no_grad():
        for (batch, targets) in extract_loader:  # each batch is a tuple from TensorDataset
            batch = batch.to(device)
            # Extract learned embeddings for SVC training
            emb = embeddings_model.extract_embeddings(batch)
            embeddings.append(emb.cpu().numpy())
            labels.append(targets.view(-1).numpy())

    # Combine all batches into giant NumPy arrays
    X_emb = np.vstack(embeddings)
    y = np.concatenate(labels)

    # Now the SVM can learn the boundaries
    svc_model.fit(X_emb, y)

    # saving models
    torch.save(embeddings_model.state_dict(), "artifacts/embedding_model.pt")

    cols_to_drop.append("Attack")
    feature_cols = feature_cols.drop("Attack")
    print(feature_cols.shape)
    joblib.dump(
        {
            "svc_model": svc_model,
            "scaler": scaler,
            "cols_to_drop": cols_to_drop,
            "input_size": input_size,
            "embedding_dim": 16,
            "class_names": ["Benign", "Recon / scanning", "Brute force attacks", "DoS / DDoS attacks", "High severity / exploitation attacks"],
            "feature_cols": feature_cols,
            "medians": medians.to_dict(),
            "clip_lower": lower.to_dict(),
            "clip_upper": upper.to_dict(),
    },"artifacts/bundle.joblib")

    # ========== EVALUATION ON TEST SET ==========
    print("\n" + "=" * 60)
    print("=" * 60)

    # scale test set with the SAME scaler
    X_test_scaled = scaler.transform(X_test)
    X_test_scaled_tensor = torch.from_numpy(X_test_scaled).float().to(device)

    # Extract test embeddings for SVC prediction    embeddings_model.eval()
    with torch.no_grad():
        X_svm_test = embeddings_model.extract_embeddings(X_test_scaled_tensor).cpu().numpy()

    # SVC predictions + scores
    y_test = y_test.view(-1).numpy()
    y_pred = svc_model.predict(X_svm_test)
    scores = svc_model.decision_function(X_svm_test)
    probs = F.softmax(torch.tensor(scores), dim=1).numpy()
    confidences = probs[np.arange(len(y_pred)), y_pred]
    class_names = ["Benign", "Recon / scanning", "Brute force attacks", "DoS / DDoS attacks", "Exploitation attacks"]

    # classification report (precision / recall / F1 per class)
    print("\nClassification report:")
    print(classification_report(
        y_test, y_pred,
        target_names=class_names, digits=4, zero_division=0
    ))

    # ROC-AUC + PR-AUC
    y_test_bin = label_binarize(y_test, classes=[0, 1, 2, 3, 4])
    try:
        roc_auc = roc_auc_score(y_test_bin, probs,
                                multi_class="ovr", average="macro")
        print(f"ROC-AUC (macro OvR): {roc_auc:.4f}")
    except ValueError as e:
        print(f"ROC-AUC skipped: {e}")

    try:
        pr_auc = average_precision_score(y_test_bin, scores, average="macro")
        print(f"PR-AUC  (macro):     {pr_auc:.4f}")
    except ValueError as e:
        print(f"PR-AUC skipped: {e}")

    # Save structured metrics for the Model Insights page
    metrics = {
        "report": classification_report(
            y_test, y_pred, target_names=class_names,
            digits=4, zero_division=0, output_dict=True
        ),
        "confusion_matrix": confusion_matrix(
            y_test, y_pred, labels=list(range(5))
        ).tolist(),
        "class_names": class_names,
    }
    try:
        metrics["roc_auc_macro"] = float(roc_auc)
    except NameError:
        pass
    try:
        metrics["pr_auc_macro"] = float(pr_auc)
    except NameError:
        pass

    with open("artifacts/metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    print("Saved metrics.json")
    # confusion matrix plot
    plt.figure(figsize=(10, 7))
    sns.heatmap(
        confusion_matrix(y_test, y_pred, labels=list(range(5))),
        annot=True, fmt="d", cmap="Blues",
        xticklabels=class_names, yticklabels=class_names
    )
    plt.title("Confusion Matrix")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.tight_layout()
    plt.savefig("artifacts/confusion_matrix.png", bbox_inches="tight", dpi=120)
    plt.show()

    # per-class one-vs-rest confusion matrices
    fig, axes = plt.subplots(1, 5, figsize=(20, 4))
    mcm = multilabel_confusion_matrix(y_test, y_pred, labels=list(range(5)))
    for i, m in enumerate(mcm):
        sns.heatmap(m, annot=True, fmt="d", cmap="Greens",
                    ax=axes[i], cbar=False)
        axes[i].set_title(class_names[i])
        axes[i].set_xlabel("Pred")
        axes[i].set_ylabel("True")
    plt.suptitle("One-vs-Rest confusion matrices", y=1.05)
    plt.tight_layout()
    plt.savefig("artifacts/cm_ovr.png", bbox_inches="tight", dpi=120)
    plt.show()

    print("\nDone — artifacts and plots saved to artifacts/")

train_and_evaluate("C:/Users/Daniel/PycharmProjects/Final_Proj_Anoseek/datasets/NF-CSE-CIC-IDS2018-v2.csv")

