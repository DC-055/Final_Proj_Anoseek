import numpy
import torch
from sklearn.svm import SVC
from torchvision import transforms
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    roc_auc_score,
    average_precision_score,
)
import time
import matplotlib.pyplot as plt
import seaborn as sns
import torch.nn.functional as F
from imblearn.over_sampling import SMOTE
from sklearn.metrics import multilabel_confusion_matrix

""" Phase 0 """
### 0.1: GPU Usage ###
device = torch.device("cpu")
#device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
#print(f"Using {device}")

### 0.2: Data Size ###
data_size = 50000

""" Phase 1 Data Import and Preprocessing """
### 1.1: Data Import, Severity Map ###

df = pd.read_csv("C:/Users/Daniel/PycharmProjects/Final_Proj_Anoseek/datasets/NF-UNSW-NB15-v2_50000.csv")
# now we'll remove the unwanted features which aren't numerical
cols_to_drop = [
    "IPV4_SRC_ADDR", "IPV4_DST_ADDR",
    "L4_SRC_PORT", "L4_DST_PORT",
    "IN_PKTS", "OUT_PKTS",
    "TCP_FLAGS", "CLIENT_TCP_FLAGS",
    "MAX_TTL", "ICMP_TYPE",
    "RETRANSMITTED_IN_PKTS", "RETRANSMITTED_OUT_PKTS",
]
df = df.drop(columns=cols_to_drop, errors='ignore')

# convertion of Attack severity to numbers
severity_dict = {
    "Benign": 0, 'Reconnaissance': 1, 'Fuzzers': 2, 'Generic': 2,
    'DoS': 3, 'Default_Attack': 3, 'Exploits': 4, 'Shellcode': 4,
    'Worms': 4, 'Backdoor': 4
}

df['Attack'] = df['Attack'].map(severity_dict)

X = df.iloc[:, :-2].values  # all rows of all features without the label and attack type
y = df.iloc[:, -1:].values  # all rows of attack type (severity)

# convertion to Tensors
X = torch.from_numpy(X).float()
y = torch.tensor(y, dtype=torch.long)

# data split
X_train, X_test, y_train_tensor, y_test = (
    train_test_split(X, y, test_size=0.25, random_state=42)
)
print("y_test positive\n",y_test[y_test[:, 0] == 1])
# dropping anomalies from training
#mask = (y_train[:, 0] == 0)
#X_train = X_train[mask]
#y_train = y_train[mask]

### 1.2: Feature Scaling ###

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_train_scaled_tensor = torch.from_numpy(X_train_scaled).float()
smote = SMOTE(random_state=42)
X_resampled_np, y_resampled_np = smote.fit_resample(X_train_scaled, y_train_tensor)
# Convert resampled data back to Tensors for windowing
X_resampled_tensor = torch.from_numpy(X_resampled_np).float()
y_resampled_tensor = torch.from_numpy(y_resampled_np).long()

### 1.3: Time Series Windowing ###

X_seq_list = []
y_seq_list = []
seq_size = 1
#print(f"Poor people's debugger: \n {X_train_scaled_tensor.shape[0]}")
num_sequences = X_resampled_tensor.shape[0] # num of sequences
input_size = X_train_scaled_tensor.shape[1] # num of features

for i in range(num_sequences - seq_size + 1):
    # X
    window_X = X_resampled_tensor[i: i + seq_size, :]
    window_y = y_resampled_tensor[i + seq_size - 1]
    # y
    X_seq_list.append(window_X)
    y_seq_list.append(window_y)

# Stack all windows into one tensor: [num_sequences, seq_len, input_size]
X_seq = torch.stack(X_seq_list, dim=0)
y_seq = torch.stack(y_seq_list, dim=0)
print("X_seq shape:", X_seq.shape)  # [num_sequences, seq_size, num_features]
print("y_seq shape:", y_seq.shape)  # [num_sequences, seq_size, num_features]

""" Phase 2 Model Architecture Design """

### 2.1: Class Model ###
class LSTM(nn.Module):
    def __init__(self, inp_size, hidden_dim):
        super().__init__()
        self.device = device
        self.lstm = nn.LSTM(input_size=inp_size, hidden_size=hidden_dim, batch_first=True)
        self.classifier = nn.Linear(hidden_dim, 5)

    def forward(self, x, return_hidden = False):
        _, (h_n, _) = self.lstm(x)
        if return_hidden:
            return h_n[-1] # for the SVM
        return self.classifier(h_n[-1]) # for CrossEntropy training


""" Phase 3: Dataset, DataLoader, and training loop """

### 3.1: Variables ###

lstm_model = LSTM(input_size, 64)
svc_model = SVC(kernel='rbf', C = 0.5, decision_function_shape='ovr')

criterion = nn.CrossEntropyLoss()
optimizer = torch.optim.Adam(lstm_model.parameters(), lr=1e-03, weight_decay=1e-05)

batch_size = 64
num_epochs = 15

### 3.2: Create DataLoader for batched training ###

dataset = TensorDataset(X_seq, y_seq) # unsupervised: inputs only
loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

### 3.2 Training loop ###

for epoch in range(num_epochs):
    lstm_model.train()
    epoch_loss = 0.0
    for (batch, targets) in loader: # each batch is a tuple from TensorDataset
        # batch: [batch_size, seq_len, input_size]
        batch = batch.to(device)
        # forward
        vector = lstm_model(batch)
        # loss
        # targets shape is [64, 1, 1], we want [64]
        loss = criterion(vector, targets.view(-1).long())
        # backward
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

lstm_model.eval()
all_features = []
all_targets = []
with torch.no_grad():
    for (batch, targets) in loader:  # each batch is a tuple from TensorDataset
        # batch: [batch_size, seq_len, input_size]
        batch = batch.to(device)
        # We need the hidden state h_n, not the classifier output
        _, (h_n, _) = lstm_model.lstm(batch)
        # h_n[-1] is [batch, hidden_dim]
        all_features.append(h_n[-1].cpu().numpy())
        all_targets.append(targets.view(-1).numpy())

# Combine all batches into giant NumPy arrays
X_svm_train = np.vstack(all_features)
y_svm_train = np.concatenate(all_targets)

# Now the SVM can learn the boundaries
svc_model.fit(X_svm_train, y_svm_train)

""" Phase 4: Result and Test """

timer_start = time.perf_counter()

### 4.3 Build test sequences and labels ###
def build_sequences_with_labels(X_tensor, y_tensor, seq_len):
    """
    Inputs:
        X_tensor - shape [N, num_features]
        y_tensor - shape [N, 2] where y[:,0] = label (0=benign, 1=attack)
        seq_len  - window size

    Returns:
        X_seq  - tensor [num_sequences, seq_len, num_features]
        y_seq  - tensor [num_sequences] containing label 0 or 1
    """
    X_windows = []
    y_severity = []
    N = X_tensor.shape[0]

    for i in range(N - seq_len + 1):
        # build sequence window
        X_windows.append(X_tensor[i:i+seq_len, :])

        # label of LAST flow in the sequence
        y_severity.append(y_tensor[i + seq_len - 1, 0].item())

    X_seq = torch.stack(X_windows, dim=0)
    y_sev_seq = torch.tensor(y_severity, dtype=torch.long)
    return X_seq, y_sev_seq

### 4.4 Usage on the test set ###

# a) scale X_test using SAME scaler as training
X_test_scaled = scaler.transform(X_test)
X_test_scaled_tensor = torch.from_numpy(X_test_scaled).float()

# b) build sequences + labels
X_test_seq, y_test_seq_sev = build_sequences_with_labels(
    X_test_scaled_tensor, y_test, seq_size
)

print("X_test_seq:", X_test_seq.shape)
print("y_test_seq:", y_test_seq_sev.shape)

### 4.5 Compute full anomaly-detection score ###
lstm_model.eval()
with torch.no_grad():
    # Pass the whole test set (if it fits in memory)
    # and get the HIDDEN state
    X_svm_test = lstm_model(X_test_seq, return_hidden=True).cpu().numpy()

# Now the SVM uses its boundaries to predict the severity
y_pred = svc_model.predict(X_svm_test)

# Final Visualization
# This generates a list of 2x2 matrices
mcm = multilabel_confusion_matrix(y_test_seq_sev.numpy(), y_pred)
fig, axes = plt.subplots(1, 5, figsize=(20, 4))
class_names = ["Benign", "Reconnaissance", "Fuzzers/Generic", "DoS/Default", "Exploits/Other"]
for i, matrix in enumerate(mcm):
    sns.heatmap(matrix, annot=True, fmt='d', cmap='Greens', ax=axes[i], cbar=False)
    axes[i].set_title(f'Class: {class_names[i]}')
    axes[i].set_xlabel('Pred')
    axes[i].set_ylabel('True')

plt.tight_layout()
plt.suptitle('One-vs-Rest Confusion Matrices per Category', fontsize=16, y=1.1)
plt.show()

plt.figure(figsize=(10, 7))
sns.heatmap(confusion_matrix(y_test_seq_sev.numpy(), y_pred),
            annot=True, fmt='d', cmap='Blues',
            xticklabels=class_names,
            yticklabels=class_names)
# Explicitly setting the labels with padding
plt.title('Final Model Performance: Attack Severity Classification', fontsize=16, pad=20)
plt.xlabel('PREDICTED SEVERITY', fontsize=12, labelpad=15, fontweight='bold')
plt.ylabel('ACTUAL (TRUE) SEVERITY', fontsize=12, labelpad=15, fontweight='bold')

# This is the magic line that prevents clipping!
plt.tight_layout()
plt.show()

# Use decision function scores for multiclass metrics
scores = svc_model.decision_function(X_svm_test)
# Convert SVM decision scores to torch tensor, apply softmax, then back to numpy
probabilities = F.softmax(torch.tensor(scores), dim=1).numpy()
# Now use these probabilities for the AUC calculation
roc_auc = roc_auc_score(y_test_seq_sev, probabilities, multi_class='ovr')
# PR-AUC usually requires one-hot encoded labels for multiclass in sklearn
from sklearn.preprocessing import label_binarize
y_test_bin = label_binarize(y_test_seq_sev, classes=[0, 1, 2, 3, 4])
pr_auc = average_precision_score(y_test_bin, scores, average="macro")

print(f"ROC-AUC: {roc_auc:.4f}")
print(f"PR-AUC:  {pr_auc:.4f}")

timer = time.perf_counter() - timer_start
print(f"Time: {timer:.4f} seconds")

