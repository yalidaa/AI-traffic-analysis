import torch
import torch.nn as nn
import torch.nn.functional as F


class TripletLoss(nn.Module):
    def __init__(self, margin: float = 0.5):
        super().__init__()
        self.triplet = nn.TripletMarginLoss(margin=margin, p=2)

    def forward(self, anchor_vec, pos_vec, neg_vec):
        return self.triplet(anchor_vec, pos_vec, neg_vec)


class JointLoss(nn.Module):
    def __init__(
        self,
        triplet_margin: float = 0.5,
        cls_weight: float = 1.0,
        triplet_weight: float = 1.0,
        label_smoothing: float = 0.0,
    ):
        super().__init__()
        self.cls_weight = cls_weight
        self.triplet_weight = triplet_weight
        self.triplet = nn.TripletMarginLoss(margin=triplet_margin, p=2)
        self.ce = nn.CrossEntropyLoss(label_smoothing=label_smoothing)

    def forward(self, anchor_proj, pos_proj, neg_proj, anchor_logits, labels):
        triplet_loss = self.triplet(anchor_proj, pos_proj, neg_proj)
        cls_loss = self.ce(anchor_logits, labels)
        total_loss = self.cls_weight * cls_loss + self.triplet_weight * triplet_loss
        return total_loss, cls_loss.detach(), triplet_loss.detach()
