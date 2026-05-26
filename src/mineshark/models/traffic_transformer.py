import torch
import torch.nn as nn
import torch.nn.functional as F


class TrafficTransformer(nn.Module):
    def __init__(
        self,
        vocab_size: int = 2002,
        seq_len: int = 128,
        embed_dim: int = 128,
        num_heads: int = 4,
        num_layers: int = 2,
        ff_dim: int = 256,
        dropout: float = 0.1,
        num_classes: int = 2,
    ):
        super().__init__()

        self.seq_len = seq_len

        self.size_embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.dir_embedding = nn.Embedding(3, embed_dim, padding_idx=0)
        self.iat_projection = nn.Linear(1, embed_dim)

        self.pos_embedding = nn.Parameter(torch.zeros(1, seq_len, embed_dim))

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=num_heads,
            dim_feedforward=ff_dim,
            dropout=dropout,
            batch_first=True,
            activation="gelu",
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        self.projection_head = nn.Sequential(
            nn.Linear(embed_dim, embed_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(embed_dim, 64),
        )

        self.classifier_head = nn.Sequential(
            nn.Linear(embed_dim, 64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_classes),
        )

    def forward(self, size_seq, iat_seq, dir_seq, attention_mask=None):
        x_size = self.size_embedding(size_seq)
        x_dir = self.dir_embedding(dir_seq)
        x_iat = self.iat_projection(iat_seq)

        seq = size_seq.size(1)
        x = x_size + x_dir + x_iat + self.pos_embedding[:, :seq, :]

        key_padding_mask = None
        if attention_mask is not None:
            key_padding_mask = ~attention_mask.bool()

        x = self.transformer_encoder(x, src_key_padding_mask=key_padding_mask)

        if attention_mask is not None:
            valid = attention_mask.float().unsqueeze(-1)
            pooled = (x * valid).sum(dim=1) / valid.sum(dim=1).clamp_min(1.0)
        else:
            pooled = x.mean(dim=1)

        projected = F.normalize(self.projection_head(pooled), p=2, dim=1)
        logits = self.classifier_head(pooled)

        return projected, logits
