# code ran on kaggle

import torch
from tqdm import tqdm
import json
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
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
import os
from cuml.svm import SVC

# Set Matplotlib backend for headless cloud execution
plt.switch_backend('Agg')

def train_and_evaluate(dataset_csv_path):
    """ Phase 0 """
    # Ensure the artifacts directory exists on Kaggle
    os.makedirs("artifacts", exist_ok=True)

    ### 0.1: GPU Usage ###
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using {device}")

    ### 0.2: Data Size ###
    #data_size = 1000000 

    """ Phase 1 Data Import and Preprocessing """
    #df = pd.read_csv(dataset_csv_path, nrows=data_size)

    # 1. Define the specific row intervals where you found the Exploitation flows
    intervals = [
        (100000, 200000),
        (600000, 700000),
        (800000, 900000)
    ]
    
    chunks = []
    for start, end in intervals:
        print(f"Extracting rows {start} to {end}...")
        
        # header=0 reads the column names first, then skips everything up to 'start'
        chunk = pd.read_csv(
            dataset_csv_path, 
            skiprows=range(1, start), 
            nrows=(end - start),
            header=0
        )
        chunks.append(chunk)
        
    df = pd.concat(chunks, ignore_index=True)
    
    
    # We DO NOT drop IN_PKTS and OUT_PKTS anymore, as packet metrics are essential 
    # to recognize automated DDoS streams vs benign requests.
    cols_to_drop = [
        "MAX_TTL",
        "RETRANSMITTED_OUT_PKTS",
        "DNS_TTL_ANSWER", "FTP_COMMAND_RET_CODE",
        "Label",
        "SRC_TO_DST_AVG_THROUGHPUT", 
        "DST_TO_SRC_AVG_THROUGHPUT",
        "SRC_TO_DST_SECOND_BYTES", 
        "DST_TO_SRC_SECOND_BYTES"
    ]
    df = df.drop(columns=cols_to_drop, errors='ignore')
    
    severity_dict = {
        "Benign": 0,
        "Infilteration": 1, "Bot": 1,
        "SSH-Bruteforce": 2, "FTP-BruteForce": 2, "Brute Force -Web": 2,
        "DoS attacks-Slowloris": 3, "DoS attacks-Hulk": 3, "DoS attacks-GoldenEye": 3,
        "DoS attacks-SlowHTTPTest": 3, "DDoS attacks-LOIC-HTTP": 3, "DDOS attack-HOIC": 3,
        "DDOS attack-LOIC-UDP": 3,
        "SQL Injection": 4, "Brute Force -XSS": 4
    }
    
    df['Attack'] = df['Attack'].map(severity_dict)
    df = df.dropna(subset=['Attack'])
    
    # Isolate feature columns before handling sequence transformations
    feature_cols = df.columns.drop(["Attack", "IPV4_SRC_ADDR", "IPV4_DST_ADDR"], errors='ignore')
    
    # Handle infinite boundaries and extract numerical layouts
    df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan)
    
    # ------------------- LSTM SEQUENCING PROCESS -------------------
    print("Reconstructing chronological flows into behavioral sequences...")
    seq_length = 2  # Length of the sliding time window per IP
    
    X_sequences = []
    y_sequences = []
    
    # Grouping by source host IP to track continuous behaviors over time
    for _, group in df.groupby("IPV4_SRC_ADDR"): # Group by src_ip without using the actual address
        # Identify the most severe event type present within this host's traffic pool
        max_severity = group['Attack'].max()

        # ADAPTIVE GUARD: If the group contains critical, low-volume exploits (Classes 1 or 4),
        # lower the minimum requirement to 2 flows so we don't erase them from existence.
        #min_flows_required = 1 if max_severity in [1, 4] else 2
        
        # If a host has fewer lines than the window size, we pad it with its own duplication
        #if len(group) < min_flows_required: 
        #    continue # Let the LSTM ignore single-packet noise
        if len(group) < seq_length:
            padding_needed = seq_length - len(group)
            padded_group = pd.concat([group] + [group.iloc[[-1]]] * padding_needed) # Concating a list to df
            features = padded_group[feature_cols].values # Filtering columns and converting to np.array
            targets = padded_group['Attack'].values
            X_sequences.append(features)
            y_sequences.append(targets[-1])
        else:
            features = group[feature_cols].values
            targets = group['Attack'].values
            # Roll a sliding window down this host's chronological logs
            for i in range(len(group) - seq_length + 1):
                X_sequences.append(features[i : i + seq_length])
                # Sequence classification maps to the label of the LAST event in the timeline
                y_sequences.append(targets[i + seq_length - 1])
                
    X_seq_arr = np.array(X_sequences, dtype=np.float32)
    y_seq_arr = np.array(y_sequences, dtype=np.int32)
    
    # Split sequential flows cleanly
    X_train_seq, X_test_seq, y_train_arr, y_test_arr = train_test_split(
        X_seq_arr, y_seq_arr, test_size=0.2, random_state=42, stratify=y_seq_arr
    )
    
    # Handle missing features and clipping logic safely over the flattened 2D metrics
    N_train, S, F_dim = X_train_seq.shape # N - number of sequences, S = sequence length, F_dim = features
    N_test = X_test_seq.shape[0]

    # # -1 instructs NumPy to automatically combines N_train × S. The resulting shape is (N_train * S, F_dim)
    X_train_flat = X_train_seq.reshape(-1, F_dim)
    X_test_flat = X_test_seq.reshape(-1, F_dim)
    
    # Creates a temporary training DataFrame. Every timestep of every sequence becomes an individual row.
    tmp_train_df = pd.DataFrame(X_train_flat, columns=feature_cols)
    tmp_test_df = pd.DataFrame(X_test_flat, columns=feature_cols)
    
    medians = tmp_train_df.median(numeric_only=True)
    lower = tmp_train_df.quantile(0.001, numeric_only=True)
    upper = tmp_train_df.quantile(0.999, numeric_only=True)
    
    tmp_train_df = tmp_train_df.fillna(medians).clip(lower=lower, upper=upper, axis=1)
    tmp_test_df = tmp_test_df.fillna(medians).clip(lower=lower, upper=upper, axis=1)
    
    # Scale variables
    scaler = StandardScaler()
    X_train_scaled_flat = scaler.fit_transform(tmp_train_df.values)
    X_test_scaled_flat = scaler.transform(tmp_test_df.values)
    
    # Reshape back to 3D Tensors for the LSTM [Batch, Seq Length, Features]
    X_train_tensor = torch.tensor(X_train_scaled_flat.reshape(N_train, S, F_dim), dtype=torch.float32)
    X_test_tensor = torch.tensor(X_test_scaled_flat.reshape(N_test, S, F_dim), dtype=torch.float32)
    
    y_train_tensor = torch.tensor(y_train_arr, dtype=torch.long)
    y_test = torch.tensor(y_test_arr, dtype=torch.long)
    
    input_size = F_dim

    """ Phase 2 Model Architecture Design """
    class NetworkLSTMEmbeddings(nn.Module):
        def __init__(self, inp_size, hidden_size, num_layers, num_classes, embedding_dim):
            super().__init__()
            self.hidden_size = hidden_size
            self.num_layers = num_layers
            
            # Sequence extraction processing
            self.lstm = nn.LSTM(
                input_size=inp_size,
                hidden_size=hidden_size,
                num_layers=num_layers,
                batch_first=True,
                dropout=0.11 if num_layers > 1 else 0.0
            )
            
            # Compress final hidden state to your fixed embedding output space
            self.embedding_bottleneck = nn.Sequential(
                nn.Linear(hidden_size, embedding_dim),
                nn.ReLU()
            )
            self.classifier = nn.Linear(embedding_dim, num_classes)

        def forward(self, x):
            # Map temporal steps through LSTM
            out, _ = self.lstm(x)
            # Use only the last structural time-step's output context
            last_timestep = out[:, -1, :]
            embedding = self.embedding_bottleneck(last_timestep)
            return self.classifier(embedding)

        def extract_embeddings(self, x):
            out, _ = self.lstm(x)
            return self.embedding_bottleneck(out[:, -1, :])

    embedding_dim = 30
    hidden_size = 32
    num_layers = 2
    
    embeddings_model = NetworkLSTMEmbeddings(
        inp_size=input_size, 
        hidden_size=hidden_size, 
        num_layers=num_layers, 
        num_classes=5, 
        embedding_dim=embedding_dim
    ).to(device)
    
    svc_model = SVC(kernel='rbf', C=0.95, decision_function_shape='ovr', class_weight='balanced')
    # To balance heavily skewed classes without spatial distortion (SMOTE),
    # compute class weight balancing directly for Cross Entropy Loss optimization
    class_counts = np.bincount(y_train_arr, minlength=5)
    # Replaces any zero counts with 1 to avoid dividing by zero 
    # if a class happens to be missing in a specific training split
    class_counts = np.where(class_counts == 0, 1, class_counts)
    weights = [0.05, 45.0, 5.0, 0.5, 300.0]
    # Multiple by 5 so the average weight will be 1.0 (as with no weights), 
    # but will see differences between classes
    weights = weights / np.sum(weights) * 5.0
    loss_weights = torch.tensor(weights, dtype=torch.float32).to(device)
    
    criterion = nn.CrossEntropyLoss(weight=loss_weights)
    optimizer = torch.optim.Adam(embeddings_model.parameters(), lr=1e-03, weight_decay=1e-05)

    batch_size = 512
    num_epochs = 13

    dataset = TensorDataset(X_train_tensor, y_train_tensor)
    train_loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, num_workers=2, pin_memory=True)
    extract_loader = DataLoader(dataset, batch_size=batch_size, shuffle=False, num_workers=2, pin_memory=True)

    print("Training Sequence LSTM...")
    for epoch in range(num_epochs):
        embeddings_model.train()
        progress_bar = tqdm(train_loader, desc=f"Epoch {epoch + 1}/{num_epochs}", unit="batch")
        for (batch, targets) in progress_bar:
            batch = batch.to(device)
            targets = targets.view(-1).long().to(device)
            logits = embeddings_model(batch)
            loss = criterion(logits, targets)
            
            optimizer.zero_grad() # Clears out the gradients from the previous batch
            loss.backward()
            optimizer.step()
            progress_bar.set_postfix({"Loss": f"{loss.item():.4f}"})

    embeddings_model.eval()
    embeddings, labels = [], []
    with torch.no_grad():
        for (batch, targets) in extract_loader:
            batch = batch.to(device)
            emb = embeddings_model.extract_embeddings(batch)
            embeddings.append(emb.cpu().numpy())
            labels.append(targets.view(-1).numpy().astype(np.int32))
    
    X_emb = np.vstack(embeddings)
    y = np.concatenate(labels)

    # Protects system stability. If your sequence dataset exceeds 100,000 arrays, 
    # it downsamples them to prevent the Support Vector Machine from completely exhausting your system RAM.
    # Protects system stability while preserving extreme minority structures
    if len(y) > 100000:
        print(f"Downsampling SVM data proportionally to preserve class ratios...")
        
        # Calculate what fraction of the data we need to keep to hit ~100,000 total rows
        keep_fraction = 100000 / len(y)
        
        unique_cls, counts = np.unique(y, return_counts=True)
        keep_indices = []
        
        for c in unique_cls:
            cls_idx = np.where(y == c)[0]
            
            # 1. For extreme minority classes, keep 100% AND over-sample if it's class 4
            if len(cls_idx) < 500:
                if c == 4:
                    print(f"Applying strategic over-sampling to Exploitation attacks (Class 4)...")
                    # Duplicate the rows 15 times to give the SVM enough identical points to form a boundary
                    oversampled_idx = np.tile(cls_idx, 230) 
                    keep_indices.extend(oversampled_idx)
                else:
                    keep_indices.extend(cls_idx)
                    
            # 2. For major classes, scale down proportionally
            else:
                sampled_size = int(len(cls_idx) * keep_fraction)
                sampled_size = max(1, min(sampled_size, len(cls_idx))) 
                
                np.random.seed(42)
                sampled_idx = np.random.choice(cls_idx, size=sampled_size, replace=False)
                keep_indices.extend(sampled_idx)
                
        X_emb = X_emb[keep_indices]
        y = y[keep_indices]
        print(f"Proportional SVM distribution: {dict(zip(*np.unique(y, return_counts=True)))}")
    
    print("Fitting GPU cuML SVM Classifier...")
    svc_model.fit(X_emb, y)

    print("Training calibrated Scikit-Learn SVM (CPU)...")
    from sklearn.svm import SVC as SklearnSVC
    from sklearn.calibration import CalibratedClassifierCV

    # Unlike svc definition above, this is used for data calibration in the near future.
    base_svc = SklearnSVC(kernel='rbf', C=0.95, decision_function_shape='ovr')
    # Find the absolute minimum count among your active classes
    unique_classes, class_counts = np.unique(y, return_counts=True)
    min_class_count = np.min(class_counts)
    # Set the folds (cv) to be min(3, min_class_count).
    # If a class only has 1 or 2 examples, cv will lower itself to match, preventing the crash.
    # If a class has 1 example, cv=1 is invalid for StratifiedKFold, so we fallback to a simple dummy CV or 2-fold.
    n_folds = max(2, min(3, min_class_count))
    # If a class has fewer than 2 examples, CalibratedClassifierCV cannot split it. 
    # In that case, we override cv with a pre-split strategy or manually bound it.
    if min_class_count < 2:
        print("Warning: Extreme minority class detected. Forcing cv='prefit' to avoid validation split crashes.")
        # We fit the base estimator first, then pass it as 'prefit'
        base_svc.fit(X_emb, y)
        sklearn_svc = CalibratedClassifierCV(estimator=base_svc, cv='prefit')
    else:
        sklearn_svc = CalibratedClassifierCV(estimator=base_svc, cv=n_folds, n_jobs=-1)
        sklearn_svc.fit(X_emb, y)
    
    if "Attack" not in cols_to_drop:
        cols_to_drop.append("Attack")
    
    joblib.dump({
        "svc_model": sklearn_svc,
        "scaler": scaler,
        "cols_to_drop": cols_to_drop,
        "input_size": input_size,
        "embedding_dim": embedding_dim,
        "class_names": ["Benign", "Recon / scanning", "Brute force attacks", "DoS / DDoS attacks", "High severity / exploitation attacks"],
        "feature_cols": feature_cols,
        "medians": medians.to_dict(),
        "clip_lower": lower.to_dict(),
        "clip_upper": upper.to_dict(),
    }, "artifacts/bundle.joblib")
    
    torch.save(embeddings_model.state_dict(), "artifacts/embedding_model.pt")
    
    # ========== EVALUATION ON TEST SET ==========
    print("\n" + "=" * 60)

    # CREATE A SAFE TEST LOADER TO PREVENT CUDA OUT OF MEMORY
    test_dataset = TensorDataset(X_test_tensor)
    test_loader = DataLoader(test_dataset, batch_size=512, shuffle=False)

    print("Extracting test embeddings in safe batches...")
    test_embeddings = []
    
    with torch.no_grad():
        for (batch_x,) in test_loader:
            batch_x = batch_x.to(device)
            emb = embeddings_model.extract_embeddings(batch_x)
            test_embeddings.append(emb.cpu().numpy())
            
    # Combine the safe batch pieces back into a single matrix for the SVM
    X_svm_test = np.vstack(test_embeddings)

    y_test = y_test.ravel().numpy()
    y_pred = sklearn_svc.predict(X_svm_test)
    probs = sklearn_svc.predict_proba(X_svm_test)
    scores = probs
    
    # DYNAMIC CLASS HANDLING: Identify exactly which classes exist in this run
    present_classes = np.unique(np.concatenate([y, y_test, y_pred]))
    num_present_classes = len(present_classes)
    
    # Map raw severity IDs to contiguous index spaces to prevent IndexError
    class_map = {actual_id: idx for idx, actual_id in enumerate(present_classes)}
    y_pred_mapped = np.array([class_map[val] for val in y_pred])
    
    # Normalize decision scores via Softmax safely over actual output width
    probs = F.softmax(torch.tensor(scores), dim=1).numpy()
    
    # Setup readable labels matching only what's present
    all_class_names = ["Benign", "Recon / scanning", "Brute force attacks", "DoS / DDoS attacks", "Exploitation attacks"]
    active_class_names = [all_class_names[i] for i in present_classes]

    print("\nClassification report:")
    print(classification_report(
        y_test, y_pred,
        labels=present_classes,
        target_names=active_class_names, 
        digits=4, 
        zero_division=0
    ))

    # ROC-AUC + PR-AUC calculations safely binarized
    y_test_bin = label_binarize(y_test, classes=present_classes)
    if num_present_classes > 1:
        if num_present_classes == 2 and y_test_bin.shape[1] == 1:
            y_test_bin = np.hstack((1 - y_test_bin, y_test_bin))
        try:
            roc_auc = roc_auc_score(y_test_bin, probs, multi_class="ovr", average="macro")
            print(f"ROC-AUC (macro OvR): {roc_auc:.4f}")
        except Exception as e:
            print(f"ROC-AUC skipped: {e}")

        try:
            pr_auc = average_precision_score(y_test_bin, scores, average="macro")
            print(f"PR-AUC  (macro):     {pr_auc:.4f}")
        except Exception as e:
            print(f"PR-AUC skipped: {e}")

    # Save metrics
    metrics = {
        "report": classification_report(
            y_test, y_pred, 
            labels=present_classes,
            target_names=active_class_names, 
            digits=4, 
            zero_division=0, 
            output_dict=True
        ),
        "confusion_matrix": confusion_matrix(y_test, y_pred, labels=present_classes).tolist(),
        "class_names": active_class_names,
    }
    with open("artifacts/metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    # Confusion matrix plots
    plt.figure(figsize=(10, 7))
    sns.heatmap(
        confusion_matrix(y_test, y_pred, labels=present_classes),
        annot=True, fmt="d", cmap="Blues",
        xticklabels=active_class_names, yticklabels=active_class_names
    )
    plt.title("Confusion Matrix")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.tight_layout()
    plt.savefig("artifacts/confusion_matrix.png", bbox_inches="tight", dpi=120)
    plt.close()

    # Per-class matrices
    fig, axes = plt.subplots(1, num_present_classes, figsize=(4 * num_present_classes, 4), squeeze=False)
    mcm = multilabel_confusion_matrix(y_test, y_pred, labels=present_classes)
    for i, m in enumerate(mcm):
        sns.heatmap(m, annot=True, fmt="d", cmap="Greens", ax=axes[0, i], cbar=False)
        axes[0, i].set_title(active_class_names[i])
        axes[0, i].set_xlabel("Pred")
        axes[0, i].set_ylabel("True")

    plt.suptitle("One-vs-Rest confusion matrices", y=1.05)
    plt.tight_layout()
    plt.savefig("artifacts/cm_ovr.png", bbox_inches="tight", dpi=120)
    plt.close()

    print("\nDone — artifacts and plots saved to artifacts/")

# Execute script using your provided file path
train_and_evaluate("/kaggle/input/datasets/dc0000/nf-cse-cic-ids2018-v1m-sample-csv/NF-CSE-CIC-IDS2018-v1M_sample.csv")