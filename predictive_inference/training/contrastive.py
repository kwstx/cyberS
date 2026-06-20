import torch
import torch.nn as nn
import logging
import random

logger = logging.getLogger("ContrastiveLearning")

class TripletMarginLossModule(nn.Module):
    def __init__(self, margin: float = 1.0):
        super(TripletMarginLossModule, self).__init__()
        self.loss_fn = nn.TripletMarginLoss(margin=margin, p=2)

    def forward(self, anchor_embed, positive_embed, negative_embed):
        """
        Compute triplet margin loss.
        Embeddings are the latent representations extracted from the MultiModalFusionEngine.
        """
        return self.loss_fn(anchor_embed, positive_embed, negative_embed)

def sample_triplets(batch_data):
    """
    Given a batch of data, sample (anchor, positive, negative) triplets based on category.
    Returns lists of indices for anchors, positives, and negatives.
    """
    anchors = []
    positives = []
    negatives = []
    
    categories = [item["category"] for item in batch_data]
    n = len(batch_data)
    
    for i in range(n):
        cat_i = categories[i]
        
        # Find positives (same category)
        pos_indices = [j for j in range(n) if j != i and categories[j] == cat_i]
        # Find negatives (different category)
        neg_indices = [j for j in range(n) if categories[j] != cat_i]
        
        if pos_indices and neg_indices:
            anchors.append(i)
            positives.append(random.choice(pos_indices))
            negatives.append(random.choice(neg_indices))
            
    return anchors, positives, negatives
