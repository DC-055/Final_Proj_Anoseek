import torch.nn as nn

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

    def build_embeddings_model(self):
        embeddings = Embeddings(self, self.inp_size, self.embedding_dim)
        return embeddings
