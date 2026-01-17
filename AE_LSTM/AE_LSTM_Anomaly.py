import numpy
import torch
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
y = df.iloc[:, -2:].values  # all rows of label and attack type

# convertion to Tensors
X = torch.from_numpy(X).float()
y = torch.tensor(y, dtype=torch.long)

# data split
X_train, X_test, y_train, y_test = (
    train_test_split(X, y, test_size=0.4, random_state=42)
)
print("y_test positive\n",y_test[y_test[:, 0] == 1])
# dropping anomalies from training
mask = (y_train[:, 0] == 0)
X_train = X_train[mask]
y_train = y_train[mask]

### 1.2: Feature Scaling ###

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_train_scaled_tensor = torch.from_numpy(X_train_scaled).float()

### 1.3: Time Series Windowing ###

X_seq_list = []
seq_size = 1
#print(f"Poor people's debugger: \n {X_train_scaled_tensor.shape[0]}")
num_sequences = X_train_scaled_tensor.shape[0] # num of sequences
input_size = X_train_scaled_tensor.shape[1] # num of features

for i in range(num_sequences - seq_size + 1):
    # X
    window = X_train_scaled_tensor[i: i + seq_size, :]
    # y
    X_seq_list.append(window)

# Stack all windows into one tensor: [num_sequences, seq_len, input_size]
X_seq = torch.stack(X_seq_list, dim=0)
print("X_seq shape:", X_seq.shape)  # [num_sequences, seq_size, num_features]

""" Phase 2 Model Architecture Design """

### 2.1: Class Model ###
class AutoencoderLSTM(nn.Module):
    def __init__(self, input_size, latent_size):
        super().__init__()
        self.device = device
        self.intermediate_size = 16

        self.encoder_lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=self.intermediate_size,
            batch_first=True
        )

        self.encoder_linear = nn.Linear(
            self.intermediate_size,
            latent_size
        )

        # Decoder: latent_size → latent_size (we'll map to input_size with a Linear)
        self.decoder_linear = nn.Linear(
            latent_size,
            self.intermediate_size
        )

        self.decoder_lstm = nn.LSTM(
            input_size=self.intermediate_size,
            hidden_size=self.intermediate_size,
            batch_first=True
        )

        # Map decoder hidden state back to original feature space
        self.output_layer = nn.Linear(self.intermediate_size, input_size)

    def forward(self, x):
        # x: [batch, seq_len, input_size]
        batch_size, seq_len, _ = x.size()  # values for decompression later

        # ---- ENCODER ----
        # output: [batch, seq_len, latent_size]
        # h_n: [1, batch, latent_size]
        _, (h_n, c_n) = self.encoder_lstm(x)

        # latent: [batch, latent_size]
        latent = torch.relu(self.encoder_linear(h_n[-1]))  # the last LSTM layer for all sequences in the batch

        # ---- DECODER INPUT ----
        # repeat latent across seq_len steps: [batch, _ -> 1 -> seq_len, latent_size]
        decoder_input_init = torch.relu(self.decoder_linear(latent))
        latent_seq = decoder_input_init.unsqueeze(1).repeat(1, seq_len, 1)

        # the decoder is now creating a time-dependent reconstruction
        # each time step has its own hidden state
        dec_output, _ = self.decoder_lstm(latent_seq)

        # map back to input feature size, per time step
        recon = self.output_layer(dec_output)  # [batch, seq_len, input_size]

        return recon

""" Phase 3: Dataset, DataLoader, and training loop """

### 3.1: Variables ###

latent_size = 3
model = AutoencoderLSTM(input_size, latent_size).to(device)

criterion = nn.MSELoss()
optimizer = torch.optim.Adam(model.parameters(), lr=1e-03, weight_decay=1e-05)

batch_size = 64
num_epochs = 15

### 3.2: Create DataLoader for batched training ###

dataset = TensorDataset(X_seq) # unsupervised: inputs only
loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

### 3.2 Training loop ###
epoch_recon_ls = []
outputs = []
for epoch in range(num_epochs):
    model.train()
    epoch_loss = 0.0
    num_sequences_epoch = 0
    for (batch,) in loader: # each batch is a tuple from TensorDataset
        # batch: [batch_size, seq_len, input_size]
        batch = batch.to(device)
        # forward
        recon = model(batch)
        # loss
        loss = criterion(recon, batch)
        # backward
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        # Accumulate loss
        epoch_recon_ls.append(recon.detach().cpu())
        batch_size_actual = batch.size(0)
        epoch_loss += loss.item() * batch_size_actual # in order to calculate weighted average
        num_sequences_epoch += batch_size_actual

    avg_epoch_loss = epoch_loss / num_sequences_epoch
    print(f'Epoch: {epoch+1} | Loss: {avg_epoch_loss:.6f}')

epoch_MSE_np = torch.cat(epoch_recon_ls, dim=0).numpy()
""" Phase 4: Result and Test """

timer_start = time.perf_counter()

### 4.1 Compute reconstruction errors for any dataset ###
def compute_reconstruction_errors(model, X_seq, device, batch_size=64):
    """
    returns:
        numpy array of shape [num_sequences] containing the MSE
        reconstruction error for each sequence.
    """

    model.eval()  # put model in eval mode
    errors = []  # we'll store all errors here

    # DataLoader lets us compute errors in batches instead of one by one
    loader = DataLoader(TensorDataset(X_seq), batch_size=batch_size, shuffle=False)

    with torch.no_grad():  # disable gradients for evaluation (faster, saves memory)
        for (batch,) in loader:  # DataLoader returns (data,) tuples
            batch = batch.to(device)

            # model output: same shape as batch → [B, seq_len, input_size]
            recon = model(batch)

            # compute reconstruction error per sequence:
            # for each sequence in the batch → mean((x - recon)^2) over time+features
            batch_errors = torch.mean((recon - batch) ** 2, dim=(1, 2)) # MSE

            # move errors back to CPU and store
            errors.append(batch_errors.cpu())

    # concatenate all error tensors into a single array
    errors = torch.cat(errors).numpy()
    return errors

### 4.2 Compute training reconstruction errors + choose threshold ###

# compute MSE per sequence on benign training sequences (X_seq is your training windows)
train_errors = compute_reconstruction_errors(model, X_seq, device)

# choose threshold = X-th percentile of benign errors
threshold_critical_percentile_top = 95
threshold_critical_percentile_bottom = 91
threshold_high_percentile_top = 98
threshold_high_percentile_bottom = 95
threshold_medium_percentile_top = 100
threshold_medium_percentile_bottom = 98
threshold_low_percentile_top = 91
threshold_low_percentile_bottom = 84
threshold_normal_percentile = 84

threshold_normal = np.percentile(train_errors, threshold_normal_percentile)
threshold_low_top = np.percentile(train_errors, threshold_low_percentile_top)
threshold_low_bottom = np.percentile(train_errors, threshold_low_percentile_bottom)
threshold_medium_top = np.percentile(train_errors, threshold_medium_percentile_top)
threshold_medium_bottom = np.percentile(train_errors, threshold_medium_percentile_bottom)
threshold_high_top = np.percentile(train_errors, threshold_high_percentile_top)
threshold_high_bottom = np.percentile(train_errors, threshold_high_percentile_bottom)
threshold_critical_top = np.percentile(train_errors, threshold_critical_percentile_top)
threshold_critical_bottom = np.percentile(train_errors, threshold_critical_percentile_bottom)

#print(f"Chosen threshold ({threshold_92_percentile}th percentile): {threshold_92:.6f}")


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
    y_labels = []
    y_severity = []
    N = X_tensor.shape[0]

    for i in range(N - seq_len + 1):
        # build sequence window
        X_windows.append(X_tensor[i:i+seq_len, :])

        # label of LAST flow in the sequence
        y_labels.append(y_tensor[i + seq_len - 1, 0].item())
        y_severity.append(y_tensor[i + seq_len - 1, 1].item())

    X_seq = torch.stack(X_windows, dim=0)
    y_seq = torch.tensor(y_labels, dtype=torch.long)
    y_sev_seq = torch.tensor(y_severity, dtype=torch.long)
    return X_seq, y_seq, y_sev_seq

### 4.4 Usage on the test set ###

# a) scale X_test using SAME scaler as training
X_test_scaled = scaler.transform(X_test)
X_test_scaled_tensor = torch.from_numpy(X_test_scaled).float()

# b) build sequences + labels
X_test_seq, y_test_seq, y_test_seq_sev = build_sequences_with_labels(
    X_test_scaled_tensor, y_test, seq_size
)

print("X_test_seq:", X_test_seq.shape)
print("y_test_seq:", y_test_seq.shape)

# compute test reconstruction errors
test_errors = compute_reconstruction_errors(model, X_test_seq, device)
# convert errors -> predictions
# truth labels (0=benign, 1=attack)
y_true = y_test_seq.numpy()
print(y_test_seq)
# predictions: 1 = anomaly (attack), 0 = benign
y_pred = (test_errors >= threshold_normal).astype(int)
print(np.add.reduce(y_pred))
low_y_pred = ((threshold_low_top > test_errors) & (test_errors >= threshold_low_bottom)).astype(int)
print(np.add.reduce(low_y_pred))
medium_y_pred = ((threshold_medium_top > test_errors) & (test_errors >= threshold_medium_bottom)).astype(int)
print(np.add.reduce(medium_y_pred))
high_y_pred = ((threshold_high_top > test_errors) & (test_errors >= threshold_high_bottom)).astype(int)
print(np.add.reduce(high_y_pred))
critical_y_pred = ((threshold_critical_top >= test_errors) & (test_errors >= threshold_critical_bottom)).astype(int)
print(np.add.reduce(critical_y_pred))

print("\nConfusion Matrix for Severity 1 - Low:")
print(confusion_matrix(y_test_seq_sev == 1, low_y_pred))
print("\nConfusion Matrix for Severity 2 - Medium:")
print(confusion_matrix(y_test_seq_sev == 2, medium_y_pred))
print("\nConfusion Matrix for Severity 3 - High:")
print(confusion_matrix(y_test_seq_sev == 3, high_y_pred))
print("\nConfusion Matrix for Severity 4 - Critical:")
print(confusion_matrix(y_test_seq_sev == 4, critical_y_pred))


### 4.5 Compute full anomaly-detection score ###

print("\nConfusion Matrix:")
print(confusion_matrix(y_true, y_pred))

print("\nClassification Report:")
print(classification_report(y_true, y_pred, target_names=["Benign", "Attack"]))

# ROC-AUC using continuous errors
roc_auc = roc_auc_score(y_true, test_errors)
pr_auc = average_precision_score(y_true, test_errors)

print(f"ROC-AUC: {roc_auc:.4f}")
print(f"PR-AUC:  {pr_auc:.4f}")

timer = time.perf_counter() - timer_start
print(f"Time: {timer:.4f} seconds")

